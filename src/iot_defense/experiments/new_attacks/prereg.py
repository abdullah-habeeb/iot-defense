"""The pre-registration: what is decided, by whom, before a single response to a new attack is measured.

`config/experiments/new_attacks/preregistration.yaml` holds, for each new attack, the mechanism class its priors come from (an
existing class, whose numbers were committed long before this attack existed, or a new class whose numbers a blind author writes,
each with a written reason), the rule-based playbook's response, and the success criteria. `freeze` validates it, hashes every
file that decides or grades, and writes FREEZE.json. `verify_freeze` is run before every measurement and every analysis.

Blindness is a declaration plus evidence, not a proof: the file names the people who wrote the numbers and states whether they had
seen any measurement. What the experiment adds is that nothing can then change unnoticed, and that the timestamps of the commit,
the push and the first measured row can be compared (evidence.py).
"""

from __future__ import annotations

import copy
import time
from pathlib import Path
from typing import Any

import yaml

from iot_defense.experiments.new_attacks import common
from iot_defense.experiments.new_attacks.scenarios import NEW_ATTACK_KEYS

# The actions that have a containment prior in config/policies.yaml; every other action contains nothing by construction
# (ALLOW, ALERT, FORENSIC_CAPTURE), so a new class needs numbers for exactly these seven.
PRIOR_ACTIONS = ("ISOLATE", "QUARANTINE", "BLOCK_SOURCE", "THROTTLE", "RESET_SESSIONS", "DECOY", "BANDWIDTH_CAP")
MIN_RATIONALE_CHARS = 40
PLACEHOLDER_MARKERS = ("todo", "tbd", "fixme", "???", "fill in")
STATUS_TEMPLATE = "TEMPLATE"
STATUS_READY = "READY"


def load(path: Path | None = None) -> dict[str, Any]:
    with (path or common.PREREG_PATH).open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def known_classes(base_model: dict[str, Any]) -> set[str]:
    classes = set(base_model["attack_class"].values())
    for per_class in base_model["containment_prior"].values():
        classes.update(per_class)
    return classes


def _text_problem(label: str, value: Any, minimum: int = 1) -> str | None:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        return f"{label}: missing" if minimum == 1 else f"{label}: needs a written reason of at least {minimum} characters"
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return f"{label}: still contains a placeholder"
    return None


def validate(prereg: dict[str, Any], base_model: dict[str, Any], *, require_ready: bool = True) -> list[str]:
    """Every reason the pre-registration cannot be frozen yet (empty list = valid)."""
    from iot_defense.defense.decision import DefenseAction

    problems: list[str] = []
    if prereg.get("schema_version") != 1:
        problems.append("schema_version must be 1")
    status = prereg.get("status")
    if require_ready and status != STATUS_READY:
        problems.append(f"status is {status!r}; the blind author must finish the file and set status: {STATUS_READY}")

    criteria = prereg.get("success_criteria") or {}
    regret = criteria.get("stackelberg_max_regret")
    if not isinstance(regret, (int, float)) or isinstance(regret, bool) or regret <= 0:
        problems.append("success_criteria.stackelberg_max_regret must be a positive number")
    if not isinstance(criteria.get("stackelberg_not_worse_than_playbook"), bool):
        problems.append("success_criteria.stackelberg_not_worse_than_playbook must be true or false")

    declaration = prereg.get("blind_declaration") or {}
    for field in ("priors_author", "playbook_author", "date_written"):
        problem = _text_problem(f"blind_declaration.{field}", declaration.get(field))
        if problem:
            problems.append(problem)
    if declaration.get("saw_new_attack_measurements") is not False:
        problems.append("blind_declaration.saw_new_attack_measurements must be false (the author must not have seen any)")
    if not isinstance(declaration.get("saw_outcome_table"), bool):
        problems.append("blind_declaration.saw_outcome_table must be true or false (state it honestly)")

    attacks = prereg.get("attacks") or {}
    if set(attacks) != set(NEW_ATTACK_KEYS):
        problems.append(f"attacks must be exactly {sorted(NEW_ATTACK_KEYS)}, found {sorted(attacks)}")
    classes = known_classes(base_model)
    action_names = {a.value for a in DefenseAction}
    for key in NEW_ATTACK_KEYS:
        entry = attacks.get(key)
        if not isinstance(entry, dict):
            continue
        where = f"attacks.{key}"
        klass = entry.get("attack_class")
        if klass == "NEW":
            new_class = entry.get("new_class") or {}
            name = new_class.get("name")
            problem = _text_problem(f"{where}.new_class.name", name)
            if problem:
                problems.append(problem)
            elif name in classes:
                problems.append(f"{where}.new_class.name {name!r} already exists; choose attack_class: {name} instead")
            priors = new_class.get("containment_prior") or {}
            reasons = new_class.get("rationale") or {}
            for action in PRIOR_ACTIONS:
                value = priors.get(action)
                if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0.0 <= float(value) <= 1.0:
                    problems.append(f"{where}.new_class.containment_prior.{action}: a number between 0 and 1 is required")
                problem = _text_problem(f"{where}.new_class.rationale.{action}", reasons.get(action), MIN_RATIONALE_CHARS)
                if problem:
                    problems.append(problem)
            extra = sorted(set(priors) - set(PRIOR_ACTIONS))
            if extra:
                problems.append(f"{where}.new_class.containment_prior has unknown actions: {extra}")
        elif klass in classes:
            pass
        else:
            problems.append(f"{where}.attack_class must be one of {sorted(classes)} or NEW, found {klass!r}")
        problem = _text_problem(f"{where}.class_rationale", entry.get("class_rationale"), MIN_RATIONALE_CHARS)
        if problem:
            problems.append(problem)
        playbook = entry.get("playbook_response")
        if playbook not in action_names:
            problems.append(f"{where}.playbook_response must be one of {sorted(action_names)}, found {playbook!r}")
        problem = _text_problem(f"{where}.playbook_rationale", entry.get("playbook_rationale"), MIN_RATIONALE_CHARS)
        if problem:
            problems.append(problem)
        analog = entry.get("nearest_known_attack")
        if analog is not None and analog not in set(base_model["attack_class"]):
            problems.append(f"{where}.nearest_known_attack must be one of the 20 known attack types, found {analog!r}")
        elif analog is None:
            problems.append(f"{where}.nearest_known_attack: name the known attack this one most resembles (used for the 'borrow the nearest measured attack' baseline)")
    return problems


def playbook_actions(prereg: dict[str, Any]) -> dict[str, Any]:
    from iot_defense.defense.decision import DefenseAction

    return {key: DefenseAction(prereg["attacks"][key]["playbook_response"]) for key in NEW_ATTACK_KEYS}


def augmented_model(prereg: dict[str, Any], base_model: dict[str, Any]) -> dict[str, Any]:
    """A copy of policy.game_model in which the two new attacks have a class. Existing classes and numbers are never changed;
    a NEW class only adds a column to each action's containment_prior."""
    model = copy.deepcopy(base_model)
    for key in NEW_ATTACK_KEYS:
        entry = prereg["attacks"][key]
        if entry["attack_class"] == "NEW":
            new_class = entry["new_class"]
            name = new_class["name"]
            for action in PRIOR_ACTIONS:
                model["containment_prior"].setdefault(action, {})[name] = float(new_class["containment_prior"][action])
            model["attack_class"][key] = name
        else:
            model["attack_class"][key] = entry["attack_class"]
    return model


def class_of(prereg: dict[str, Any], key: str) -> str:
    entry = prereg["attacks"][key]
    return entry["new_class"]["name"] if entry["attack_class"] == "NEW" else entry["attack_class"]


# ── freeze ────────────────────────────────────────────────────────────────────

def _section_digest(name: str) -> str:
    from iot_defense.defense.objective import load_policy_section

    return common.sha256_text(common.canonical_json(load_policy_section(name)))


def build_manifest(root: Path | None = None) -> dict[str, Any]:
    root = root or common.REPO_ROOT
    files = {}
    for relative in common.FROZEN_FILES:
        path = root / relative
        files[relative] = common.sha256_file(path) if path.exists() else None
    table = root / "data" / "outcomes" / "outcome_table.jsonl"
    rows = root / "data" / "experiments" / "new_attacks" / "rows.jsonl"
    return {
        "schema_version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "created_at_epoch": time.time(),
        "git_head_at_freeze": common.git("rev-parse", "HEAD", root=root),
        "files": files,
        "game_model_sha256": _section_digest("game_model"),
        "objective_sha256": _section_digest("objective"),
        "main_outcome_table_sha256": common.sha256_file(table) if table.exists() else None,
        "rows_state": {"exists": rows.exists(), "lines": len(common.read_jsonl(rows))},
    }


def verify_freeze(manifest_path: Path | None = None, root: Path | None = None) -> list[str]:
    """Every way the current tree differs from the frozen one (empty list = identical)."""
    import json

    manifest_path = manifest_path or common.FREEZE_PATH
    if not manifest_path.exists():
        return [f"{manifest_path} does not exist: the pre-registration has not been frozen"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems = []
    current = build_manifest(root)
    for relative, digest in manifest["files"].items():
        if current["files"].get(relative) != digest:
            problems.append(f"{relative} changed since the freeze")
    for field in ("game_model_sha256", "objective_sha256", "main_outcome_table_sha256"):
        if current[field] != manifest[field]:
            problems.append(f"{field} changed since the freeze")
    return problems


def main() -> None:
    """`python -m iot_defense.experiments.new_attacks.prereg freeze` validates and writes FREEZE.json."""
    import argparse
    import json

    from iot_defense.defense.objective import load_policy_section

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["validate", "freeze"])
    args = parser.parse_args()
    prereg = load()
    problems = validate(prereg, load_policy_section("game_model"), require_ready=True)
    if problems:
        print("The pre-registration cannot be frozen:")
        for problem in problems:
            print(" -", problem)
        raise SystemExit(1)
    print("pre-registration is valid")
    if args.command == "validate":
        return
    rows_exist = common.ROWS_PATH.exists() and common.read_jsonl(common.ROWS_PATH)
    if rows_exist:
        print("REFUSING to freeze: measured rows already exist, so the priors could not be blind to them.")
        raise SystemExit(1)
    dirty = common.git("status", "--porcelain")
    if dirty:
        print("REFUSING to freeze with uncommitted changes (the manifest must describe committed files):\n" + dirty)
        raise SystemExit(1)
    manifest = build_manifest()
    common.FREEZE_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {common.FREEZE_PATH}")
    print("Next: commit it, push, then record the push time on GitHub (docs/NEW_ATTACKS_PROTOCOL.md step 5).")


if __name__ == "__main__":
    main()
