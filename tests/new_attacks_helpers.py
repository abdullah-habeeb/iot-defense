"""Shared builders for the new-attacks tests: a complete pre-registration and synthetic measured rows."""

from __future__ import annotations

import copy
from typing import Any

import yaml

from iot_defense.defense.decision import DefenseAction
from iot_defense.evaluation.outcome import Measurement

REASON = "The response acts on the traffic in a way the mechanism makes plain, and this sentence is long enough to be a reason."

VALID_PREREG: dict[str, Any] = {
    "schema_version": 1,
    "status": "READY",
    "title": "t",
    "claim": "a claim",
    "success_criteria": {"stackelberg_max_regret": 1.0, "stackelberg_not_worse_than_playbook": True},
    "blind_declaration": {
        "priors_author": "A. Author", "playbook_author": "A. Author", "date_written": "2026-11-02",
        "saw_new_attack_measurements": False, "saw_outcome_table": False,
    },
    "attacks": {
        "ssdp_reflection": {
            "mechanism": "m", "attack_class": "reflection", "class_rationale": REASON,
            "playbook_response": "BANDWIDTH_CAP", "playbook_rationale": REASON, "nearest_known_attack": "dns_amplification",
        },
        "telnet_scan_outbound": {
            "mechanism": "m", "attack_class": "outbound", "class_rationale": REASON,
            "playbook_response": "QUARANTINE", "playbook_rationale": REASON, "nearest_known_attack": "data_exfiltration",
        },
    },
}


def valid_prereg() -> dict[str, Any]:
    return copy.deepcopy(VALID_PREREG)


def write_prereg(path, spec: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")


def new_class_entry(name: str = "scan_out") -> dict[str, Any]:
    priors = {"ISOLATE": 1.0, "QUARANTINE": 0.9, "BLOCK_SOURCE": 0.2, "THROTTLE": 0.3, "RESET_SESSIONS": 0.1, "DECOY": 0.1, "BANDWIDTH_CAP": 0.0}
    return {"name": name, "containment_prior": priors, "rationale": {a: REASON for a in priors}}


# containment, service lost, intelligence verified
DEFAULT_PROFILE: dict[str, tuple[float, float, bool]] = {
    "ALLOW": (0.0, 0.0, False), "ALERT": (0.0, 0.0, False), "FORENSIC_CAPTURE": (0.0, 0.0, True), "ISOLATE": (1.0, 1.0, False),
    "QUARANTINE": (0.9, 0.35, False), "BLOCK_SOURCE": (1.0, 0.0, False), "THROTTLE": (0.3, 0.1, False),
    "RESET_SESSIONS": (0.0, 0.1, False), "DECOY": (0.2, 0.05, True), "BANDWIDTH_CAP": (0.8, 0.0, False),
}


def block_rows(condition: str, rep: int, profile: dict[str, tuple[float, float, bool]], measured_at: str) -> list[dict[str, Any]]:
    rows = []
    for position, action in enumerate(["ALLOW", *[a.value for a in DefenseAction if a != DefenseAction.ALLOW], "ALLOW"]):
        containment, loss, intel = profile[action]
        residual = 100 if action == "ALLOW" else round((1.0 - containment) * 100)
        measurement = Measurement(condition, DefenseAction(action), "success", 100, residual, loss, intel)
        rows.append({**measurement.to_row(), "rep": rep, "order_index": position, "seed": 11, "detected_condition": "normal",
                     "probe_error": None, "measured_at": measured_at})
    return rows


def synthetic_rows(profiles: dict[str, dict[str, tuple[float, float, bool]]], reps: int = 3, start: str = "2026-11-02T10:00:00+0000") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    minute = 0
    for rep in range(reps):
        for condition, profile in profiles.items():
            rows += block_rows(condition, rep, profile, start[:14] + f"{minute:02d}:00+0000")
            minute += 1
    return rows
