"""Measured outcomes against an attacker that REACTS to the response.

The standard outcome table (evaluation/outcome.py) scores one response against one burst of
attack traffic. That cannot distinguish a response that stops the attack from one that only stops
the attacker's first address: both look contained. Here the attack runs for two rounds against the
same, still-active response, and between them a scripted reactive attacker decides what to do:

    round 1   the attack, from the attacker's own address
    reaction  if round 1 was mitigated (it delivered under MITIGATED_FRACTION of what the
              un-responded attack delivers), the attacker switches to a fresh source address;
              otherwise it carries on unchanged
    round 2   the attack again, from wherever the reaction put it

Each round is measured exactly like a standard probe (iptables counter on the receiving host,
legitimate-service pings), and the episode utility is the shared objective averaged over the two
rounds, with intelligence counted once and the action's cost once:

    u = mean over rounds of [ containment * (1 - residual_r / baseline_r)  +  service * (1 - loss_r) ]
        + intelligence * intel_verified  -  action_cost

THIS IS A THREAT MODEL, NOT A DISCOVERY. The attacker is scripted to react this way, and the
reaction is triggered by the harness reading the attacker's own counter, which stands in for the
attacker noticing its traffic is impeded. What the measurement shows is how each response fares
against such an attacker; it does not show that real attackers behave this way.

Only attacks that can be re-sent from a spoofed source are covered (UDP/ICMP/SYN-only floods and
UDP replay): a TCP exchange cannot complete from an address the sender does not own.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import fmean
from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective
from iot_defense.evaluation.outcome import MIN_BASELINE_PACKETS, OutcomeTable

# Attacks with a spoofable single-source variant (see TrafficGenerator's *_distributed generators).
ADAPTIVE_CONDITIONS = ("dos_flood", "tcp_syn_flood", "icmp_ping_flood", "credential_replay")
# An address the attacker host can spoof that no other lab component uses.
ROTATION_SOURCE_IP = "10.0.0.131"
# Round 1 counts as mitigated when it delivered less than this fraction of the un-responded baseline.
MITIGATED_FRACTION = 0.5


def is_mitigated(residual: int, baseline: int | None) -> bool:
    """Whether the attacker would notice its traffic being impeded. Needs a usable baseline: with
    none (the very first un-responded probe of a block) nothing has been responded to, so no."""
    return baseline is not None and baseline >= MIN_BASELINE_PACKETS and residual < MITIGATED_FRACTION * baseline


def round_containment(action: DefenseAction, residual: int, baseline: int) -> float:
    """As Measurement.containment: ALLOW is the baseline itself, so 0 by definition; clipped to
    [-1, 1] so run-to-run noise on a no-op response does not read as a systematic gain."""
    if action == DefenseAction.ALLOW or baseline <= 0:
        return 0.0
    return min(1.0, max(-1.0, 1.0 - residual / baseline))


@dataclass(frozen=True, slots=True)
class AdaptiveMeasurement:
    condition: str
    action: DefenseAction
    status: str
    baseline1: int
    residual1: int
    baseline2: int
    residual2: int
    rotated: bool
    service_loss1: float
    service_loss2: float
    intel_verified: bool

    @property
    def valid(self) -> bool:
        if not (0.0 <= self.service_loss1 <= 1.0 and 0.0 <= self.service_loss2 <= 1.0):
            return False
        return self.baseline1 >= MIN_BASELINE_PACKETS and self.baseline2 >= MIN_BASELINE_PACKETS

    @property
    def containments(self) -> tuple[float, float]:
        return (
            round_containment(self.action, self.residual1, self.baseline1),
            round_containment(self.action, self.residual2, self.baseline2),
        )

    def utility(self, objective: Objective) -> float:
        c1, c2 = self.containments
        rounds = [
            objective.utility(self.action, containment=c, service=1.0 - loss, intelligence=0.0)
            for c, loss in ((c1, self.service_loss1), (c2, self.service_loss2))
        ]
        return fmean(rounds) + objective.intelligence * (1.0 if self.intel_verified else 0.0)

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row["action"] = self.action.value
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "AdaptiveMeasurement":
        return cls(
            condition=row["condition"], action=DefenseAction(row["action"]), status=row["status"],
            baseline1=int(row["baseline1"]), residual1=int(row["residual1"]),
            baseline2=int(row["baseline2"]), residual2=int(row["residual2"]), rotated=bool(row["rotated"]),
            service_loss1=float(row["service_loss1"]), service_loss2=float(row["service_loss2"]),
            intel_verified=bool(row["intel_verified"]),
        )


class AdaptiveOutcomeTable(OutcomeTable):
    """Same interface as OutcomeTable (samples / mean / best_action / sample / require_complete), so
    the PPO environment, the arbiter and the evaluation code consume it unchanged; the realized
    utility of a cell is the two-round episode utility above."""

    def __init__(self, rows: list[dict[str, Any]], objective: Objective) -> None:
        super().__init__([], objective)
        self.rotation: dict[tuple[str, DefenseAction], list[bool]] = {}
        for row in rows:
            measurement = AdaptiveMeasurement.from_row(row)
            if not measurement.valid:
                self.invalid_rows += 1
                continue
            key = (measurement.condition, measurement.action)
            self._samples[key].append(measurement.utility(objective))
            self.rotation.setdefault(key, []).append(measurement.rotated)

    def rotation_rate(self, condition: str, action: DefenseAction) -> float:
        """How often the reactive attacker switched source against this response."""
        flags = self.rotation.get((condition, action), [])
        return fmean(float(f) for f in flags) if flags else float("nan")

    @classmethod
    def from_jsonl(cls, path: str | Path, objective: Objective | None = None) -> "AdaptiveOutcomeTable":
        rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
        return cls(rows, objective or Objective.load())
