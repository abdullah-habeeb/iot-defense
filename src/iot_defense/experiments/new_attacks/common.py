"""Paths, hashing and git helpers shared by the new-attacks experiment."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
CONFIG_DIR = REPO_ROOT / "config" / "experiments" / "new_attacks"
DATA_DIR = REPO_ROOT / "data" / "experiments" / "new_attacks"
PREREG_PATH = CONFIG_DIR / "preregistration.yaml"
FREEZE_PATH = CONFIG_DIR / "FREEZE.json"
ROWS_PATH = DATA_DIR / "rows.jsonl"
RUN_LOG_PATH = DATA_DIR / "run_log.jsonl"
SMOKE_LOG_PATH = DATA_DIR / "smoke_log.jsonl"
RESULTS_JSON = DATA_DIR / "results.json"
RESULTS_MD = DATA_DIR / "results.md"
MAIN_TABLE_PATH = REPO_ROOT / "data" / "outcomes" / "outcome_table.jsonl"
POLICIES_PATH = REPO_ROOT / "config" / "policies.yaml"

# Everything that decides, generates or grades. Hashed in FREEZE.json, so none of it can change between writing the priors and
# reading the result. (evidence.py only reports and may change.)
FROZEN_FILES = (
    "config/experiments/new_attacks/preregistration.yaml",
    "config/policies.yaml",
    "src/iot_defense/experiments/new_attacks/scenarios.py",
    "src/iot_defense/experiments/new_attacks/prereg.py",
    "src/iot_defense/experiments/new_attacks/measure.py",
    "src/iot_defense/experiments/new_attacks/smoke.py",
    "src/iot_defense/experiments/new_attacks/analyze.py",
    "src/iot_defense/experiments/new_attacks/common.py",
    "src/iot_defense/defense/game_model.py",
    "src/iot_defense/defense/stackelberg.py",
    "src/iot_defense/defense/policy.py",
    "src/iot_defense/defense/model_outcomes.py",
    "src/iot_defense/evaluation/outcome.py",
    "src/iot_defense/evaluation/outcome_table.py",
    "src/iot_defense/defense/ppo_real_env.py",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def git(*args: str, root: Path | None = None, check: bool = False) -> str:
    """Run git in the repository and return stdout ('' on failure unless check)."""
    completed = subprocess.run(["git", *args], cwd=str(root or REPO_ROOT), capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        if check:
            raise RuntimeError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
        return ""
    return completed.stdout.strip()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
