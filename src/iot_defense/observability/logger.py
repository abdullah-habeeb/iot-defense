"""Simple structured logger for defense events."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StructuredLogger:
    """Record structured events to a JSON Lines log file."""

    def __init__(self, log_dir: str | Path = "data/logs") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / "events.jsonl"

    def log(self, event: dict[str, Any]) -> Path:
        """Write a single event as JSON to the event log."""
        event_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event_record) + "\n")
        return self.log_path
