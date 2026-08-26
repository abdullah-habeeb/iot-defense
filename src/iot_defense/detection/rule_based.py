"""Rule-based detector used as the initial foundation implementation."""

from __future__ import annotations

from typing import Any

from .base import DetectionModel


class RuleBasedDetector(DetectionModel):
    """A lightweight detector that flags suspicious traffic using simple thresholds."""

    def __init__(self, suspicious_threshold: float = 0.75) -> None:
        self.suspicious_threshold = suspicious_threshold

    def predict(self, features: dict[str, Any]) -> dict[str, Any]:
        score = 0.0

        if features.get("protocol") == "ICMP":
            score += 0.4
        if features.get("dst_port") in {22, 23, 3389}:
            score += 0.35
        if features.get("direction") == "inbound":
            score += 0.15
        if features.get("packet_length", 0) > 2000:
            score += 0.2

        is_suspicious = score >= self.suspicious_threshold

        return {
            "suspicious": is_suspicious,
            "score": round(score, 3),
            "label": "malicious" if is_suspicious else "benign",
            "reason": "rule_based_detection",
        }
