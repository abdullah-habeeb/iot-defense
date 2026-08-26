"""Base interfaces for detection components."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class DetectionModel(ABC):
    """Abstract detection interface for future ML or rule-based implementations."""

    @abstractmethod
    def predict(self, features: dict[str, Any]) -> dict[str, Any]:
        """Return a structured result containing the detection decision."""
