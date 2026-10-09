"""Measured response outcomes and their realized utility.

One Measurement is what live Mininet actually did after a response was
applied: how much of the attack flow survived to the receiving host's
firewall counter (see defense/ppo_real_env.py for why a counter, not a
capture), how much legitimate service survived, and whether the response
yielded verified intelligence. realized_utility() scores it with the shared objective. Nothing
here consults a registered preferred_action.
"""

from __future__ import annotations

import json
import random
from collections import defaultdict
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import Objective

# An un-responded attack that delivered fewer packets than this gives no
# meaningful baseline to compute a residual fraction against.
MIN_BASELINE_PACKETS = 3


@dataclass(frozen=True, slots=True)
class Measurement:
    condition: str
    action: DefenseAction
    status: str
    baseline_packets: int
    residual_packets: int
    service_loss: float
    intel_verified: bool

    @property
    def is_attack(self) -> bool:
        return self.condition != "normal"

    @property
    def valid(self) -> bool:
        """Whether the probe itself produced a usable reading. A response
        that failed to execute is still a valid measurement (nothing was
        applied, and the probe measured what reached the sensor anyway) --
        dropping failures would bias results toward actions that always
        work."""
        if not 0.0 <= self.service_loss <= 1.0:
            return False
        return not self.is_attack or self.baseline_packets >= MIN_BASELINE_PACKETS

    @property
    def containment(self) -> float | None:
        """Fraction of the un-responded attack's packets the response kept
        from surviving to the receiving host; None for a benign condition.
        ALLOW is the baseline itself, so its containment is 0 by definition.

        Clipped to [-1, 1], not [0, 1]: packet counts vary run to run, so a
        no-op response reads slightly above or below the baseline. Clipping
        at 0 would turn that symmetric noise into a positive bias for
        useless actions."""
        if not self.is_attack:
            return None
        if self.action == DefenseAction.ALLOW or self.baseline_packets <= 0:
            return 0.0
        return min(1.0, max(-1.0, 1.0 - self.residual_packets / self.baseline_packets))

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row["action"] = self.action.value
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Measurement":
        return cls(
            condition=row["condition"],
            action=DefenseAction(row["action"]),
            status=row["status"],
            baseline_packets=int(row["baseline_packets"]),
            residual_packets=int(row["residual_packets"]),
            service_loss=float(row["service_loss"]),
            intel_verified=bool(row["intel_verified"]),
        )


def with_baseline(measurement: Measurement, baseline_packets: int) -> Measurement:
    """The same measurement scored against the trial's un-responded baseline."""
    return replace(measurement, baseline_packets=baseline_packets)


def consensus_baseline(allow_measurements: list[Measurement]) -> int:
    """Mean surviving-packet count over a block's un-responded (ALLOW) probes.
    Averaging the before/after probes halves the baseline's run-to-run noise
    (large for unthrottled floods)."""
    if not allow_measurements or any(m.action != DefenseAction.ALLOW for m in allow_measurements):
        raise ValueError("consensus_baseline needs one or more ALLOW measurements")
    return round(sum(m.residual_packets for m in allow_measurements) / len(allow_measurements))


def realized_utility(measurement: Measurement, objective: Objective) -> float:
    return objective.utility(
        measurement.action,
        containment=measurement.containment,
        service=1.0 - measurement.service_loss,
        intelligence=1.0 if measurement.intel_verified else 0.0,
    )


class OutcomeTable:
    """Measured realized utilities per (true condition, action)."""

    def __init__(self, rows: list[dict[str, Any]], objective: Objective) -> None:
        self.objective = objective
        self._samples: dict[tuple[str, DefenseAction], list[float]] = defaultdict(list)
        self.invalid_rows = 0
        for row in rows:
            measurement = Measurement.from_row(row)
            if not measurement.valid:
                self.invalid_rows += 1
                continue
            self._samples[(measurement.condition, measurement.action)].append(
                realized_utility(measurement, objective)
            )

    @classmethod
    def from_jsonl(cls, path: str | Path, objective: Objective | None = None) -> "OutcomeTable":
        rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
        return cls(rows, objective or Objective.load())

    def samples(self, condition: str, action: DefenseAction) -> list[float]:
        return self._samples.get((condition, action), [])

    def mean(self, condition: str, action: DefenseAction) -> float:
        values = self.samples(condition, action)
        if not values:
            raise KeyError(f"no valid measurement for ({condition!r}, {action.value})")
        return sum(values) / len(values)

    def sample(self, condition: str, action: DefenseAction, rng: random.Random) -> float:
        values = self.samples(condition, action)
        if not values:
            raise KeyError(f"no valid measurement for ({condition!r}, {action.value})")
        return values[rng.randrange(len(values))]

    def best_action(self, condition: str) -> DefenseAction:
        return max(DefenseAction, key=lambda action: self.mean(condition, action))

    def missing_cells(self, conditions: tuple[str, ...]) -> list[tuple[str, str]]:
        return [
            (condition, action.value)
            for condition in conditions
            for action in DefenseAction
            if not self.samples(condition, action)
        ]

    def require_complete(self, conditions: tuple[str, ...]) -> None:
        missing = self.missing_cells(conditions)
        if missing:
            raise ValueError(
                f"outcome table has no valid measurement for {len(missing)} (condition, action) cells, "
                f"e.g. {missing[:5]}; re-run evaluation.outcome_table to fill them"
            )
