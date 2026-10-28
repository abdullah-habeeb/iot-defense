"""Validation, the augmented game model and the freeze manifest of the new-attacks pre-registration. No Mininet."""

from __future__ import annotations

import copy
import json

import pytest
from new_attacks_helpers import new_class_entry, valid_prereg, write_prereg

from iot_defense.defense.decision import DefenseAction
from iot_defense.defense.objective import load_policy_section
from iot_defense.experiments.new_attacks import common, prereg

BASE = load_policy_section("game_model")


def problems(spec, **kwargs):
    return prereg.validate(spec, BASE, **kwargs)


class TestValidation:
    def test_a_complete_pre_registration_is_valid(self):
        assert problems(valid_prereg()) == []

    def test_an_unfilled_template_is_not_ready_and_says_why(self):
        template = valid_prereg()
        template["status"] = "TEMPLATE"
        template["blind_declaration"] = {"priors_author": "", "playbook_author": "", "date_written": "",
                                         "saw_new_attack_measurements": None, "saw_outcome_table": None}
        for entry in template["attacks"].values():
            entry.update({"attack_class": "", "class_rationale": "", "playbook_response": "", "playbook_rationale": "", "nearest_known_attack": ""})
        text = " ".join(problems(template))
        assert "status is" in text and "attack_class" in text and "playbook_response" in text and "saw_new_attack_measurements" in text
        assert problems(template, require_ready=False)  # still incomplete without the status requirement

    def test_the_shipped_pre_registration_is_the_valid_frozen_one(self):
        spec = prereg.load()
        assert problems(spec) == []
        assert spec["status"] == "READY" and set(spec["attacks"]) == {"ssdp_reflection", "telnet_scan_outbound"}
        assert spec["success_criteria"] == {"stackelberg_max_regret": 1.0, "stackelberg_not_worse_than_playbook": True}
        assert all(spec["attacks"][k]["mechanism"].strip() for k in spec["attacks"])

    @pytest.mark.parametrize("path,value,fragment", [
        (("status",), "TEMPLATE", "status is"),
        (("blind_declaration", "saw_new_attack_measurements"), True, "saw_new_attack_measurements"),
        (("blind_declaration", "saw_new_attack_measurements"), None, "saw_new_attack_measurements"),
        (("blind_declaration", "saw_outcome_table"), None, "saw_outcome_table"),
        (("blind_declaration", "priors_author"), "  ", "priors_author"),
        (("success_criteria", "stackelberg_max_regret"), 0, "stackelberg_max_regret"),
        (("success_criteria", "stackelberg_max_regret"), True, "stackelberg_max_regret"),
        (("success_criteria", "stackelberg_not_worse_than_playbook"), "yes", "not_worse"),
        (("attacks", "ssdp_reflection", "attack_class"), "teleportation", "attack_class"),
        (("attacks", "ssdp_reflection", "playbook_response"), "NUKE", "playbook_response"),
        (("attacks", "ssdp_reflection", "playbook_rationale"), "short", "playbook_rationale"),
        (("attacks", "ssdp_reflection", "class_rationale"), "TODO decide later, this is long enough to pass the length check", "placeholder"),
        (("attacks", "telnet_scan_outbound", "nearest_known_attack"), "no_such_attack", "nearest_known_attack"),
        (("attacks", "telnet_scan_outbound", "nearest_known_attack"), None, "nearest_known_attack"),
    ])
    def test_each_defect_is_reported(self, path, value, fragment):
        spec = valid_prereg()
        node = spec
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
        assert any(fragment in p for p in problems(spec)), problems(spec)

    def test_the_two_attacks_are_exactly_the_registered_pair(self):
        spec = valid_prereg()
        spec["attacks"]["third"] = spec["attacks"]["ssdp_reflection"]
        assert any("attacks must be exactly" in p for p in problems(spec))

    def test_a_new_class_needs_seven_priors_and_a_reason_for_each(self):
        spec = valid_prereg()
        spec["attacks"]["telnet_scan_outbound"].update({"attack_class": "NEW", "new_class": new_class_entry()})
        assert problems(spec) == []
        for action in prereg.PRIOR_ACTIONS:
            broken = copy.deepcopy(spec)
            del broken["attacks"]["telnet_scan_outbound"]["new_class"]["containment_prior"][action]
            assert any(f"containment_prior.{action}" in p for p in problems(broken))
            broken = copy.deepcopy(spec)
            broken["attacks"]["telnet_scan_outbound"]["new_class"]["rationale"][action] = "gut feeling"
            assert any(f"rationale.{action}" in p for p in problems(broken))

    def test_a_new_class_prior_must_be_a_probability(self):
        spec = valid_prereg()
        spec["attacks"]["telnet_scan_outbound"].update({"attack_class": "NEW", "new_class": new_class_entry()})
        spec["attacks"]["telnet_scan_outbound"]["new_class"]["containment_prior"]["ISOLATE"] = 1.5
        assert any("ISOLATE" in p for p in problems(spec))

    def test_a_new_class_may_not_reuse_an_existing_name_or_add_unknown_actions(self):
        spec = valid_prereg()
        entry = new_class_entry("probing")
        spec["attacks"]["telnet_scan_outbound"].update({"attack_class": "NEW", "new_class": entry})
        assert any("already exists" in p for p in problems(spec))
        entry = new_class_entry()
        entry["containment_prior"]["ALLOW"] = 0.5
        spec["attacks"]["telnet_scan_outbound"]["new_class"] = entry
        assert any("unknown actions" in p for p in problems(spec))


class TestAugmentedModel:
    def test_existing_classes_and_numbers_are_never_changed(self):
        before = copy.deepcopy(BASE)
        model = prereg.augmented_model(valid_prereg(), BASE)
        assert BASE == before  # the base is not mutated
        for key, value in before["attack_class"].items():
            assert model["attack_class"][key] == value
        assert model["containment_prior"] == before["containment_prior"]
        assert model["attack_class"]["ssdp_reflection"] == "reflection" and model["attack_class"]["telnet_scan_outbound"] == "outbound"

    def test_a_new_class_only_adds_a_column(self):
        spec = valid_prereg()
        spec["attacks"]["telnet_scan_outbound"].update({"attack_class": "NEW", "new_class": new_class_entry("scan_out")})
        model = prereg.augmented_model(spec, BASE)
        assert model["attack_class"]["telnet_scan_outbound"] == "scan_out"
        assert model["containment_prior"]["ISOLATE"]["scan_out"] == 1.0 and model["containment_prior"]["BANDWIDTH_CAP"]["scan_out"] == 0.0
        for action, per_class in BASE["containment_prior"].items():
            for klass, value in per_class.items():
                assert model["containment_prior"][action][klass] == value
        assert prereg.class_of(spec, "telnet_scan_outbound") == "scan_out"

    def test_the_playbook_actions_are_parsed(self):
        actions = prereg.playbook_actions(valid_prereg())
        assert actions == {"ssdp_reflection": DefenseAction.BANDWIDTH_CAP, "telnet_scan_outbound": DefenseAction.QUARANTINE}


class TestFreeze:
    def test_every_frozen_file_exists_and_is_hashed(self):
        manifest = prereg.build_manifest()
        assert set(manifest["files"]) == set(common.FROZEN_FILES)
        assert all(manifest["files"].values()), [k for k, v in manifest["files"].items() if not v]

    def test_a_manifest_verifies_against_the_tree_it_was_built_from(self, tmp_path):
        path = tmp_path / "FREEZE.json"
        path.write_text(json.dumps(prereg.build_manifest()), encoding="utf-8")
        assert prereg.verify_freeze(path) == []

    def test_a_changed_file_a_changed_section_or_a_changed_benchmark_is_reported(self, tmp_path):
        manifest = prereg.build_manifest()
        manifest["files"]["src/iot_defense/experiments/new_attacks/analyze.py"] = "0" * 64
        manifest["game_model_sha256"] = "1" * 64
        manifest["main_outcome_table_sha256"] = "2" * 64
        path = tmp_path / "FREEZE.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        found = " ".join(prereg.verify_freeze(path))
        assert "analyze.py changed" in found and "game_model_sha256" in found and "main_outcome_table_sha256" in found

    def test_no_manifest_means_not_frozen(self, tmp_path):
        assert "has not been frozen" in prereg.verify_freeze(tmp_path / "missing.json")[0]

    def test_the_freeze_command_writes_a_manifest_only_for_a_valid_clean_unmeasured_state(self, tmp_path, monkeypatch):
        import sys

        spec_path, freeze_path, rows_path = tmp_path / "p.yaml", tmp_path / "FREEZE.json", tmp_path / "rows.jsonl"
        write_prereg(spec_path, valid_prereg())
        monkeypatch.setattr(common, "PREREG_PATH", spec_path)
        monkeypatch.setattr(common, "FREEZE_PATH", freeze_path)
        monkeypatch.setattr(common, "ROWS_PATH", rows_path)
        monkeypatch.setattr(sys, "argv", ["prereg", "freeze"])
        real_git = common.git
        monkeypatch.setattr(common, "git", lambda *a, **k: "" if a[:1] == ("status",) else real_git(*a, **k))

        rows_path.write_text(json.dumps({"condition": "x"}) + "\n", encoding="utf-8")
        with pytest.raises(SystemExit):
            prereg.main()  # a measured row already exists
        assert not freeze_path.exists()
        rows_path.unlink()

        monkeypatch.setattr(common, "git", lambda *a, **k: " M file.py" if a[:1] == ("status",) else real_git(*a, **k))
        with pytest.raises(SystemExit):
            prereg.main()  # dirty tree
        assert not freeze_path.exists()

        monkeypatch.setattr(common, "git", lambda *a, **k: "" if a[:1] == ("status",) else real_git(*a, **k))
        prereg.main()
        written = json.loads(freeze_path.read_text(encoding="utf-8"))
        assert set(written["files"]) == set(common.FROZEN_FILES) and "rows_state" in written

    def test_the_freeze_command_refuses_an_unfinished_template(self, monkeypatch):
        import sys

        monkeypatch.setattr(sys, "argv", ["prereg", "freeze"])
        with pytest.raises(SystemExit):
            prereg.main()
