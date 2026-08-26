"""Feature extraction utilities for observed traffic."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class FeatureExtractor:
    """Convert raw packet or flow data into a simple structured feature dictionary."""

    def __init__(self, output_dir: str | Path | None = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else Path("data/metrics")

    def extract(self, sample: dict[str, Any]) -> dict[str, Any]:
        """Extract a normalized feature vector from a packet-like observation."""
        return {
            "src_ip": sample.get("src_ip"),
            "dst_ip": sample.get("dst_ip"),
            "protocol": sample.get("protocol"),
            "packet_length": sample.get("packet_length", 0),
            "ttl": sample.get("ttl", 0),
            "src_port": sample.get("src_port"),
            "dst_port": sample.get("dst_port"),
            "timestamp": sample.get("timestamp", 0.0),
            "direction": sample.get("direction", "unknown"),
        }

    def write_metrics(self, features: dict[str, Any], filename: str = "features.jsonl") -> Path:
        """Persist extracted feature data to disk for later inspection."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.output_dir / filename
        with output_path.open("a", encoding="utf-8") as fh:
            fh.write(str(features) + "\n")
        return output_path
