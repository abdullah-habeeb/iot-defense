"""Mininet topology helpers for the foundation prototype."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class TopologyConfig:
    """Load and expose topology parameters from the YAML config file."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        base = Path(__file__).resolve().parents[2]
        self.config_path = Path(config_path) if config_path else base / "config" / "topology.yaml"
        self._data = self._load_config()

    def _load_config(self) -> dict[str, Any]:
        with self.config_path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    @property
    def name(self) -> str:
        return self._data.get("topology", {}).get("name", "iot-home-lab")

    @property
    def hosts(self) -> list[dict[str, Any]]:
        return self._data.get("topology", {}).get("hosts", [])

    @property
    def switch(self) -> dict[str, Any]:
        return self._data.get("topology", {}).get("switch", {})

    @property
    def links(self) -> list[str]:
        return self._data.get("topology", {}).get("links", [])

    @property
    def traffic(self) -> dict[str, Any]:
        return self._data.get("topology", {}).get("traffic", {})
