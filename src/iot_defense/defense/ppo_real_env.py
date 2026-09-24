"""Real-Mininet-backed Gymnasium environment for PPO fine-tuning.

Unlike ppo_env.DefenseDecisionEnv (a fast, deterministic synthetic
simulator used for the base training pass), every step() here actually
drives the real Mininet lab: it generates real traffic for the chosen
scenario, captures and detects it with the exact same pipeline the live
demo uses, executes the agent's chosen action for real, and computes a
reward from a *verified* real outcome (a real ping check for ISOLATE, a
real redirected connection for DECOY) rather than an assumed one.

This is intended for a short, bounded fine-tuning run on top of an
already-trained model -- not training from scratch. Each step costs several
real seconds (traffic generation, capture, detection, response, and a
restore-to-baseline before the next step), so total_timesteps should stay
small (tens, not thousands). Requires root (Mininet) to run.
"""

from __future__ import annotations

import time
from typing import Any, Callable

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from iot_defense.defense.context import build_security_context
from iot_defense.defense.decision import DefenseAction, DefenseDecision
from iot_defense.defense.executor import MininetResponseExecutor
from iot_defense.defense.ppo_env import (
    ACTION_TO_INDEX,
    INDEX_TO_ACTION,
    OBSERVATION_SIZE,
    TRAINING_SCENARIOS,
    RewardConfig,
    SecurityContextEncoder,
)
from iot_defense.detection.detector import UnifiedRuleBasedDetector
from iot_defense.detection.flow_features import FeatureAggregator
from iot_defense.detection.threat_event import ThreatEvent
from iot_defense.monitoring.monitor import PacketMonitor
from iot_defense.network.topology import create_mininet_network
from iot_defense.simulation.traffic import TrafficGenerator

TARGET_IP = "10.0.0.10"
ATTACKER_IP = "10.0.0.100"


class RealMininetDefenseEnv(gym.Env[np.ndarray, int]):
    """PPO training environment whose step() outcomes are real, verified
    Mininet observations instead of an assumed reward table.

    The Mininet network is created once (on the first reset()) and reused
    for the whole training run -- recreating it every episode would be far
    too slow. Every step restores the network to a clean baseline before
    returning, so consecutive steps and episodes never interfere with each
    other.
    """

    metadata = {"render_modes": []}

    def __init__(self, episode_length: int | None = None, reward_config: RewardConfig | None = None) -> None:
        super().__init__()
        self.action_space = spaces.Discrete(len(DefenseAction))
        self.observation_space = spaces.Box(0.0, 1.0, shape=(OBSERVATION_SIZE(),), dtype=np.float32)
        # Self-sizes to the scenario count, not a fixed number: a fixed
        # episode_length smaller than len(TRAINING_SCENARIOS()) means
        # whichever scenario cycles in last is only ever shown as the
        # terminal observation, never actually acted on -- so it gets no
        # training signal at all, no matter how long training runs. This
        # was a real, confirmed bug in ppo_env.DefenseDecisionEnv (fixed
        # in Phase 3); applying the same fix here pre-emptively, before
        # this env's first real use, rather than waiting to rediscover it.
        self.episode_length = episode_length if episode_length is not None else len(TRAINING_SCENARIOS())
        self.reward_config = reward_config or RewardConfig()
        self.encoder = SecurityContextEncoder()

        self.net: Any = None
        self.executor: MininetResponseExecutor | None = None
        self.traffic_gen = TrafficGenerator()
        self.monitor = PacketMonitor()
        self.aggregator = FeatureAggregator()
        self.detector = UnifiedRuleBasedDetector()

        self._step = 0
        self._scenario_index = 0
        self._pending_scenario: str | None = None
        self._pending_threat_event: ThreatEvent | None = None

    # ─── Mininet lifecycle ──────────────────────────────────────────────────

    def _ensure_network(self) -> None:
        if self.net is not None:
            return
        self.net = create_mininet_network()
        self.net.start()
        self.executor = MininetResponseExecutor(self.net)

    def close(self) -> None:
        if self.executor is not None:
            try:
                self.executor.cleanup()
            except Exception as exc:  # noqa: BLE001
                print(f"[RealMininetDefenseEnv] executor cleanup error: {exc}")
        if self.net is not None:
            try:
                self.net.stop()
            except Exception as exc:  # noqa: BLE001
                print(f"[RealMininetDefenseEnv] mininet stop error: {exc}")
        self.executor = None
        self.net = None

    # ─── Real observation for one scenario ─────────────────────────────────

    def _observe_scenario(
        self, scenario: str, traffic_override: Callable[[Any], Any] | None = None
    ) -> ThreatEvent:
        """Generate real traffic for one scenario, capture it, and classify
        it with the same attack-type-agnostic detector the live demo uses.

        Registry-driven for every non-normal scenario: this used to
        hardcode exactly two attacks (dos_flood, else-reconnaissance),
        left over from before brute-force/exfiltration existed. Left
        unfixed, it would have silently generated reconnaissance traffic
        while *labeling* it brute_force/data_exfiltration in training data
        the moment this env was first actually used -- caught and fixed
        here, before that first real use, not after.

        traffic_override, when given, replaces the registry's own
        `generate_traffic` call for this one observation (capture sizing
        still comes from the matched attack's own registry entry) -- used
        by evaluation/adaptive.py to send the *same* attack's traffic from
        a different (real or spoofed) source per round without
        duplicating this method's capture/aggregate/detect logic, the
        exact un-synced-copy bug class this project has hit before.
        """
        if scenario == "normal":
            session = self.monitor.start_capture(self.net, "sensor", 20, watchdog_seconds=63.0)
            (traffic_override or self.traffic_gen.generate_normal_mininet_traffic)(self.net)
            cap_path = self.monitor.stop_capture(self.net, session, 3.0)
        else:
            from iot_defense.attacks.registry import ATTACK_SCENARIOS

            attack = next(
                (scenario_ for scenario_ in ATTACK_SCENARIOS.values() if scenario_.attack_type == scenario),
                None,
            )
            if attack is None:
                raise ValueError(f"No registered attack scenario for training scenario: {scenario!r}")
            session = self.monitor.start_capture(
                self.net, "sensor", attack.capture_packet_limit,
                watchdog_seconds=attack.capture_completion_timeout + 60.0,
            )
            (traffic_override or attack.generate_traffic)(self.net)
            cap_path = self.monitor.stop_capture(self.net, session, attack.capture_completion_timeout)

        try:
            packets = self.monitor.read_capture(self.net, "sensor", cap_path)
        except Exception:  # noqa: BLE001
            # A capture can genuinely come back empty/corrupt under real
            # timing (the same intermittent "No data could be read!"
            # failure mode generate_dataset.py already tolerates by
            # skipping the run and continuing) -- read_capture() itself
            # already retries once, so a second failure here means this
            # is a real dry step, not a transient race. A single bad
            # capture must degrade to "no signal", not crash the whole
            # training loop: with dozens of steps per run, even a ~10%
            # per-capture failure rate would make an unguarded crash here
            # almost certain to end any real run before it finished.
            packets = []
        flows = self.aggregator.aggregate(packets)
        if flows:
            return self.detector.detect_flows(flows)
        return self.detector.detect(
            {"source_ip": ATTACKER_IP, "destination_ip": TARGET_IP,
             "unique_destination_ports": 0, "packet_count": 0, "packets_per_second": 0.0}
        )

    # ─── Real action execution + verified outcome ──────────────────────────

    def _execute_and_verify(self, action: DefenseAction, threat_event: ThreatEvent) -> dict[str, Any]:
        """Actually perform the chosen action and verify its real effect."""
        decision = DefenseDecision.create(
            action=action,
            target_ip=threat_event.destination_ip if threat_event.destination_ip != "unknown" else TARGET_IP,
            source_ip=threat_event.source_ip if threat_event.source_ip != "unknown" else ATTACKER_IP,
            reason="PPO real-Mininet fine-tuning step",
            confidence=threat_event.confidence,
            threat_score=threat_event.threat_score,
            policy_name="RealMininetDefenseEnv",
            # Real, found-not-assumed bug: an empty context here made
            # executor.execute()'s THROTTLE branch -- which reads
            # context["beliefs"]["observed_features"]["protocol"] to pick
            # a protocol-aware hashlimit rule -- always fall back to its
            # "TCP" default, regardless of the real detected protocol.
            # icmp_ping_flood is the one THROTTLE-preferred attack that
            # isn't TCP, so every real THROTTLE call for it silently
            # installed a TCP-only rule that can never match ICMP traffic,
            # while still reporting "success" (no iptables error) -- the
            # exact failure mode throttle()'s own docstring already
            # describes as found-and-fixed, except the fix was never wired
            # through this specific caller. Populating the real protocol
            # here, from this threat_event's own already-observed
            # features, is that missing wire, not a new mechanism.
            context={"beliefs": {"observed_features": {"protocol": threat_event.features.get("protocol", "TCP")}}},
        )
        result = self.executor.execute(decision)
        outcome: dict[str, Any] = {"status": result.status}

        if action == DefenseAction.ISOLATE and result.status == "success":
            camera = self.net.get("camera")
            after = camera.cmd(f"ping -c 1 -W 1 {decision.target_ip}")
            outcome["connectivity_lost"] = "100% packet loss" in after
        elif action == DefenseAction.DECOY and result.status == "success":
            try:
                attacker = self.net.get("attacker")
                decoy_ports = result.details.get("decoy_ports") or [22]
                probe = attacker.cmd(
                    "python3 - <<'PY'\n"
                    "import socket\n"
                    "try:\n"
                    f"    sock = socket.create_connection(('{decision.target_ip}', {decoy_ports[0]}), timeout=2)\n"
                    "    sock.sendall(b'GET /status')\n"
                    "    print('INTERACTION_OK:' + sock.recv(128).decode(errors='replace').strip())\n"
                    "    sock.close()\n"
                    "except Exception as exc:\n"
                    "    print(f'INTERACTION_FAILED:{exc}')\n"
                    "PY"
                ).strip()
                outcome["interaction_verified"] = "INTERACTION_OK" in probe
            except Exception:  # noqa: BLE001
                outcome["interaction_verified"] = False
        elif action == DefenseAction.THROTTLE and result.status == "success":
            try:
                target_host = self.executor._host_for_ip(decision.target_ip)
                rule_check = target_host.cmd(f"iptables -L INPUT -n | grep -c {decision.target_ip}")
                outcome["rule_installed"] = rule_check.strip() not in ("", "0")
            except Exception:  # noqa: BLE001
                outcome["rule_installed"] = False

        # Always restore before the next step so every step starts clean.
        try:
            self.executor.restore(decision.target_ip)
        except Exception:  # noqa: BLE001
            pass
        return outcome

    # ─── Reward ─────────────────────────────────────────────────────────────

    @staticmethod
    def _preferred_action_verified(preferred_action: DefenseAction, outcome: dict[str, Any], execution_ok: bool) -> bool:
        """Whether the *specific, real* outcome this preferred action needs
        to actually claim success was itself verified -- not just that
        the executor call didn't raise. Mirrors the per-action outcome
        keys _execute_and_verify() sets: a real ping check for ISOLATE, a
        real redirected connection for DECOY, a real installed-rule check
        for THROTTLE."""
        if not execution_ok:
            return False
        if preferred_action == DefenseAction.ISOLATE:
            return bool(outcome.get("connectivity_lost"))
        if preferred_action == DefenseAction.DECOY:
            return bool(outcome.get("interaction_verified"))
        if preferred_action == DefenseAction.THROTTLE:
            return bool(outcome.get("rule_installed"))
        return execution_ok

    def calculate_reward(self, scenario: str, action: DefenseAction, outcome: dict[str, Any]) -> tuple[float, dict[str, float]]:
        """Registry-driven, mirroring ppo_env.DefenseDecisionEnv's synthetic
        calculate_reward(): every attack's reward comes from its own
        registered preferred_action, so a newly registered attack needs no
        code change here -- only _execute_and_verify() needs a branch if
        its preferred action introduces a genuinely new kind of outcome to
        verify (matching the pattern already used for ISOLATE/DECOY/
        THROTTLE above).
        """
        config = self.reward_config
        components: dict[str, float] = {"response_cost": config.response_cost}
        reward = config.response_cost
        execution_ok = outcome.get("status") == "success"

        if scenario == "normal":
            if action == DefenseAction.ALLOW:
                components["service_preserved"] = config.service_preserved
                reward += config.service_preserved
            else:
                components["false_positive_intervention"] = config.false_positive_intervention
                reward += config.false_positive_intervention
                if action == DefenseAction.ISOLATE:
                    components["unnecessary_isolation"] = config.unnecessary_isolation
                    reward += config.unnecessary_isolation
            return float(reward), components

        from iot_defense.attacks.registry import ATTACK_SCENARIOS

        attack = next((s for s in ATTACK_SCENARIOS.values() if s.attack_type == scenario), None)
        if attack is None:
            raise ValueError(f"Unsupported threat type for reward calculation: {scenario!r}")

        if action == attack.preferred_action:
            if self._preferred_action_verified(attack.preferred_action, outcome, execution_ok):
                if attack.preferred_action == DefenseAction.DECOY:
                    components["attacker_diverted"] = config.attacker_diverted
                    components["intelligence_gained"] = config.intelligence_gained
                    reward += config.attacker_diverted + config.intelligence_gained
                else:
                    components["attack_contained"] = config.attack_contained
                    reward += config.attack_contained
            else:
                components["response_failed"] = config.false_positive_intervention
                reward += config.false_positive_intervention
        elif action == DefenseAction.ALLOW:
            components["successful_compromise"] = config.successful_compromise
            reward += config.successful_compromise
        else:
            components["service_disruption"] = config.service_disruption
            reward += config.service_disruption

        return float(reward), components

    # ─── Gym API ────────────────────────────────────────────────────────────

    def reset(self, *, seed: int | None = None, options: dict[str, Any] | None = None):
        super().reset(seed=seed)
        self._ensure_network()
        self._step = 0
        training_scenarios = TRAINING_SCENARIOS()
        scenario = training_scenarios[self._scenario_index % len(training_scenarios)]
        threat_event = self._observe_scenario(scenario)
        context = build_security_context(threat_event, device_criticality="high")
        self._pending_scenario = scenario
        self._pending_threat_event = threat_event
        return self.encoder.encode(context), {"scenario": scenario}

    def step(self, action: int):
        """Evaluate `action` against the state actually returned by the
        previous reset()/step() call -- not a freshly regenerated one, so
        the action is judged against what the agent actually observed.
        This also means each step costs exactly one real observation
        (not two): the state it evaluates was already captured last call,
        and only the *next* state is freshly observed here.
        """
        if action not in INDEX_TO_ACTION:
            raise ValueError(f"Invalid defense action index: {action}")
        scenario = self._pending_scenario
        threat_event = self._pending_threat_event
        selected_action = INDEX_TO_ACTION[action]

        outcome = self._execute_and_verify(selected_action, threat_event)
        reward, components = self.calculate_reward(scenario, selected_action, outcome)

        self._step += 1
        self._scenario_index += 1
        terminated = self._step >= self.episode_length

        training_scenarios = TRAINING_SCENARIOS()
        next_scenario = training_scenarios[self._scenario_index % len(training_scenarios)]
        next_threat_event = self._observe_scenario(next_scenario)
        next_context = build_security_context(next_threat_event, device_criticality="high")
        self._pending_scenario = next_scenario
        self._pending_threat_event = next_threat_event
        observation = self.encoder.encode(next_context)

        info = {"scenario": scenario, "action": selected_action.value, "outcome": outcome, "reward_components": components}
        return observation, reward, terminated, False, info
