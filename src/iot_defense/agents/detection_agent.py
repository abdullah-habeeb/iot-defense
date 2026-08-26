"""Detection agent wrapper for the rule-based detector."""

from __future__ import annotations

from typing import Any

from iot_defense.detection.base import DetectionModel
from iot_defense.detection.rule_based import RuleBasedDetector


class DetectionAgent:
    """Encapsulate the model used to judge whether a feature set is suspicious."""

    def __init__(self, model: DetectionModel | None = None) -> None:
        self.model = model or RuleBasedDetector()

    def analyze(self, features: dict[str, Any]) -> dict[str, Any]:
        """Analyze an event and return a structured suspiciousness result."""
        return self.model.predict(features)
