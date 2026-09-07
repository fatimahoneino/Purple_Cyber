"""Scenario and rule loading tests.

Loaders are the boundary with user-authored content, so the important behaviour is
that malformed input fails loudly and locally rather than silently degrading a
report. A scenario that quietly loads with zero steps would show as perfect
coverage.
"""

from __future__ import annotations

import pytest
import yaml

from purpleforge.detection.loader import load_all_rules, load_rule
from purpleforge.emulation.scenario import load_all_scenarios, load_scenario
from purpleforge.models import Severity, TechniqueRef


def write(tmp_path, name: str, payload: dict):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


class TestTechniqueRef:
    def test_base_technique_strips_subtechnique(self):
        assert TechniqueRef("T1059.001", "PowerShell", "execution").base_technique == "T1059"

    def test_base_technique_of_parent_is_itself(self):
        assert TechniqueRef("T1486", "Encrypt", "impact").base_technique == "T1486"

    def test_url_uses_navigator_path_form(self):
        ref = TechniqueRef("T1059.001", "PowerShell", "execution")
        assert ref.url.endswith("/techniques/T1059/001/")

    def test_invalid_id_is_rejected(self):
        with pytest.raises(ValueError, match="technique ids start with"):
            TechniqueRef("1059", "bad", "execution")


class TestScenarioLoading:
    def test_bundled_scenarios_have_complete_metadata(self):
        for scenario in load_all_scenarios():
            assert scenario.scenario_id
            assert scenario.name
            assert scenario.description.strip()
            assert scenario.threat_actor
            assert scenario.steps

    def test_tactics_preserve_kill_chain_order(self):
        apt29 = next(s for s in load_all_scenarios() if s.scenario_id == "PF-APT29-01")
        assert apt29.tactics[0] == "initial-access"
        assert apt29.tactics[-1] == "exfiltration"

    def test_techniques_are_deduplicated(self, tmp_path):
        path = write(
            tmp_path,
            "dup.yml",
            {
                "scenario_id": "S1",
                "name": "dup",
                "steps": [
                    {
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "tactic": "execution",
                        "telemetry": [{"process.name": "a.exe"}],
                    },
                    {
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "tactic": "execution",
                        "telemetry": [{"process.name": "b.exe"}],
                    },
                ],
            },
        )
        assert len(load_scenario(path).techniques) == 1

    def test_step_without_telemetry_is_rejected(self, tmp_path):
        """A step blue cannot observe is not a useful test."""
        path = write(
            tmp_path,
            "empty.yml",
            {
                "scenario_id": "S1",
                "name": "empty",
                "steps": [
                    {
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "tactic": "execution",
                        "telemetry": [],
                    }
                ],
            },
        )
        with pytest.raises(ValueError, match="emits no telemetry"):
            load_scenario(path)

    def test_missing_required_key_is_rejected(self, tmp_path):
        path = write(tmp_path, "bad.yml", {"name": "no id", "steps": []})
        with pytest.raises(ValueError, match="missing required keys"):
            load_scenario(path)

    def test_scenario_with_no_steps_is_rejected(self, tmp_path):
        """Silently loading an empty scenario would report perfect coverage."""
        path = write(tmp_path, "none.yml", {"scenario_id": "S1", "name": "n", "steps": []})
        with pytest.raises(ValueError, match="no steps"):
            load_scenario(path)

    def test_step_missing_technique_id_names_the_key(self, tmp_path):
        path = write(
            tmp_path,
            "bad_step.yml",
            {
                "scenario_id": "S1",
                "name": "n",
                "steps": [{"technique_name": "x", "tactic": "execution", "telemetry": [{"a": 1}]}],
            },
        )
        with pytest.raises(ValueError, match="technique_id"):
            load_scenario(path)

    def test_malformed_file_is_skipped_not_fatal(self, tmp_path, capsys):
        write(tmp_path, "broken.yml", {"name": "no id"})
        write(
            tmp_path,
            "good.yml",
            {
                "scenario_id": "OK",
                "name": "good",
                "steps": [
                    {
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "tactic": "execution",
                        "telemetry": [{"process.name": "a.exe"}],
                    }
                ],
            },
        )
        loaded = load_all_scenarios(tmp_path)
        assert [s.scenario_id for s in loaded] == ["OK"]
        assert "skipping" in capsys.readouterr().out

    def test_missing_directory_returns_empty(self, tmp_path):
        assert load_all_scenarios(tmp_path / "nope") == []


class TestRuleLoading:
    def test_bundled_rules_have_descriptions_and_false_positives(self):
        for rule in load_all_rules():
            assert rule.description.strip(), f"{rule.rule_id} has no description"
            assert rule.false_positives, f"{rule.rule_id} documents no false positives"

    def test_attack_tags_become_technique_refs(self, tmp_path):
        path = write(
            tmp_path,
            "tagged.yml",
            {
                "id": "R1",
                "title": "t",
                "tags": ["attack.execution", "attack.t1059.001"],
                "detection": {"sel": {"process.name": "a.exe"}},
                "condition": "sel",
            },
        )
        rule = load_rule(path)
        assert rule.technique_ids == {"T1059.001"}
        assert rule.techniques[0].tactic == "execution"

    def test_condition_inside_detection_block_is_accepted(self, tmp_path):
        """Sigma keeps the condition inside detection; both placements must work."""
        path = write(
            tmp_path,
            "sigma_style.yml",
            {
                "id": "R1",
                "title": "t",
                "detection": {"sel": {"process.name": "a.exe"}, "condition": "sel"},
            },
        )
        rule = load_rule(path)
        assert rule.condition == "sel"
        assert "condition" not in rule.detection

    def test_level_maps_to_severity(self, tmp_path):
        path = write(
            tmp_path,
            "crit.yml",
            {
                "id": "R1",
                "title": "t",
                "level": "critical",
                "detection": {"sel": {"a": 1}},
                "condition": "sel",
            },
        )
        assert load_rule(path).severity is Severity.CRITICAL

    def test_unknown_severity_is_rejected(self, tmp_path):
        path = write(
            tmp_path,
            "bad_sev.yml",
            {
                "id": "R1",
                "title": "t",
                "level": "apocalyptic",
                "detection": {"sel": {"a": 1}},
                "condition": "sel",
            },
        )
        with pytest.raises(ValueError, match="unknown severity"):
            load_rule(path)

    def test_missing_condition_is_rejected(self, tmp_path):
        path = write(
            tmp_path, "no_cond.yml", {"id": "R1", "title": "t", "detection": {"sel": {"a": 1}}}
        )
        with pytest.raises(ValueError, match="no condition"):
            load_rule(path)

    def test_empty_detection_is_rejected(self, tmp_path):
        path = write(tmp_path, "no_det.yml", {"id": "R1", "title": "t", "condition": "sel"})
        with pytest.raises(ValueError, match="non-empty mapping"):
            load_rule(path)

    def test_duplicate_rule_ids_are_skipped(self, tmp_path, capsys):
        for name in ("a.yml", "b.yml"):
            write(
                tmp_path,
                name,
                {
                    "id": "SAME",
                    "title": name,
                    "detection": {"sel": {"a": 1}},
                    "condition": "sel",
                },
            )
        rules = load_all_rules(tmp_path)
        assert len(rules) == 1
        assert "duplicate" in capsys.readouterr().out

    def test_fingerprint_detects_identical_logic(self, tmp_path):
        """Used to reject duplicate AI proposals."""
        common = {"detection": {"sel": {"process.name": "a.exe"}}, "condition": "sel"}
        a = load_rule(write(tmp_path, "a.yml", {"id": "A", "title": "A", **common}))
        b = load_rule(write(tmp_path, "b.yml", {"id": "B", "title": "B", **common}))
        assert a.fingerprint == b.fingerprint


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_sorting_uses_rank_not_alphabetical(self):
        ordered = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM])
        assert ordered == [Severity.LOW, Severity.MEDIUM, Severity.CRITICAL]
