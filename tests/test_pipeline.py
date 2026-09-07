"""End-to-end pipeline tests.

These assert the properties that make the whole assessment credible: telemetry is
reproducible, ground truth is honest, the noise set can actually trip the rules,
and the holdout evaluation catches rules that only work in-sample.
"""

from __future__ import annotations

import pytest

from purpleforge.ai.provider import HeuristicProvider
from purpleforge.ai.rule_author import DetectionAuthor
from purpleforge.ai.triage import AlertTriageAgent
from purpleforge.detection.engine import DetectionEngine
from purpleforge.detection.loader import load_all_rules
from purpleforge.emulation.emitter import TelemetryEmitter
from purpleforge.emulation.scenario import load_all_scenarios
from purpleforge.models import DetectionRule, Severity, TechniqueRef, utcnow
from purpleforge.pipeline import PurpleForgePipeline


@pytest.fixture(scope="module")
def scenarios():
    return load_all_scenarios()


@pytest.fixture(scope="module")
def rules():
    return load_all_rules()


@pytest.fixture(scope="module")
def result():
    return PurpleForgePipeline(provider=HeuristicProvider(), seed=1337).run()


class TestBundledContent:
    def test_scenarios_load(self, scenarios):
        assert len(scenarios) >= 3

    def test_rules_load(self, rules):
        assert len(rules) >= 10

    def test_every_bundled_rule_is_syntactically_valid(self, rules):
        assert DetectionEngine(rules).validate() == []

    def test_every_rule_declares_a_technique(self, rules):
        missing = [r.rule_id for r in rules if not r.techniques]
        assert not missing, f"rules without ATT&CK mapping: {missing}"

    def test_rule_ids_are_unique(self, rules):
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids))

    def test_every_scenario_step_emits_telemetry(self, scenarios):
        for scenario in scenarios:
            for step in scenario.steps:
                assert step.telemetry, f"{scenario.scenario_id}/{step.step_id} emits nothing"


class TestEmitter:
    def test_same_seed_is_reproducible(self, scenarios):
        """Byte-for-byte identical output, including event ids.

        base_time is pinned because timestamps would otherwise track wall clock
        and make the comparison meaningless.
        """
        clock = utcnow()
        a = TelemetryEmitter(seed=42, base_time=clock).emit(scenarios[0])
        b = TelemetryEmitter(seed=42, base_time=clock).emit(scenarios[0])
        assert [e.to_dict() for e in a] == [e.to_dict() for e in b]
        assert [e.event_id for e in a] == [e.event_id for e in b]

    def test_different_seed_changes_telemetry(self, scenarios):
        clock = utcnow()
        a = TelemetryEmitter(seed=1, base_time=clock).emit(scenarios[0])
        b = TelemetryEmitter(seed=2, base_time=clock).emit(scenarios[0])
        assert [e.flatten() for e in a] != [e.flatten() for e in b]

    def test_events_are_time_ordered(self, scenarios):
        events = TelemetryEmitter(seed=7).emit(scenarios[0])
        assert events == sorted(events, key=lambda e: e.timestamp)

    def test_every_scenario_technique_produces_labelled_events(self, scenarios):
        for scenario in scenarios:
            events = TelemetryEmitter(seed=3).emit(scenario)
            labelled = {e.technique_id for e in events if e.is_malicious}
            expected = {t.technique_id for t in scenario.techniques}
            assert expected <= labelled

    def test_benign_events_carry_no_technique_label(self, scenarios):
        events = TelemetryEmitter(seed=5).emit(scenarios[0])
        for event in events:
            if not event.is_malicious:
                assert event.technique_id is None

    def test_noise_ratio_zero_yields_only_attack_events(self, scenarios):
        events = TelemetryEmitter(seed=9, noise_ratio=0).emit(scenarios[0])
        assert all(e.is_malicious for e in events)

    def test_attacker_infrastructure_varies_by_seed(self, scenarios):
        """Holdout evaluation depends on this: identical C2 values across seeds
        would let a rule that memorised a literal IP look like a real detection."""

        def c2_values(seed: int) -> set[str]:
            events = TelemetryEmitter(seed=seed, noise_ratio=0).emit(scenarios[0])
            return {
                str(e.flatten().get("destination.ip"))
                for e in events
                if e.flatten().get("destination.ip")
            }

        assert c2_values(11) != c2_values(22)


class TestNoiseRealism:
    def test_benign_noise_can_trip_the_rules(self, scenarios, rules):
        """Precision must be earned, not free.

        If no benign event could ever match a rule, precision would be 1.0 by
        construction and the scorecard would be meaningless. This asserts the
        lookalike noise actually produces false positives.
        """
        engine = DetectionEngine(rules)
        events = TelemetryEmitter(seed=1337).emit(scenarios[0])
        alerts = engine.run(events)
        assert any(not a.is_true_positive for a in alerts)

    def test_precision_is_not_perfect(self, result):
        assert 0.0 < result.scorecard.precision < 1.0


class TestPipeline:
    def test_produces_alerts_and_coverage(self, result):
        assert result.scorecard.total_alerts > 0
        assert result.scorecard.techniques_total > 0

    def test_no_rule_errors_on_bundled_content(self, result):
        assert result.rule_errors == []

    def test_true_and_false_positives_sum_to_alert_count(self, result):
        card = result.scorecard
        assert card.true_positives + card.false_positives == card.total_alerts

    def test_detects_some_but_not_all_techniques(self, result):
        """The bundled rule set deliberately leaves gaps for the AI layer to work on."""
        card = result.scorecard
        assert 0 < card.techniques_detected < card.techniques_total

    def test_reproducible_across_runs(self):
        a = PurpleForgePipeline(provider=HeuristicProvider(), seed=99).run(author_rules=False)
        b = PurpleForgePipeline(provider=HeuristicProvider(), seed=99).run(author_rules=False)
        assert a.scorecard.to_dict()["summary"] == b.scorecard.to_dict()["summary"]

    def test_empty_rule_set_raises_rather_than_reporting_zero(self):
        with pytest.raises(RuntimeError, match="no detection rules"):
            PurpleForgePipeline(rules=[], provider=HeuristicProvider()).run()

    def test_no_scenarios_raises(self):
        with pytest.raises(RuntimeError, match="no scenarios"):
            PurpleForgePipeline(scenarios=[], provider=HeuristicProvider()).run()


class TestTriage:
    def test_all_alerts_get_a_verdict(self, result):
        assert all(a.triage for a in result.alerts)

    def test_alerts_are_ranked_by_risk(self, result):
        scores = [a.triage["risk_score"] for a in result.alerts]
        assert scores == sorted(scores, reverse=True)

    def test_scores_separate_real_detections_from_noise(self, result):
        """The point of triage. A small gap means the scores are not helping.

        The floor is set low enough to be robust to seed changes but high enough
        that a regression which flattens the scoring would fail.
        """
        assert result.triage_summary["separation"] > 15

    def test_correlated_activity_raises_the_score(self):
        """An isolated alert and a correlated one must not score the same.

        Host correlation is the strongest signal available, and scoring each alert
        in isolation throws it away.
        """
        provider = HeuristicProvider()
        base = {
            "severity": "high",
            "command_line": "powershell.exe -enc AAA",
            "tactic": "execution",
        }
        isolated = provider.score_alert({**base, "correlated_alert_count": 0})
        correlated = provider.score_alert(
            {**base, "correlated_alert_count": 8, "distinct_tactics_on_host": 4}
        )
        assert correlated["risk_score"] > isolated["risk_score"]

    def test_trusted_parent_lowers_the_score(self):
        """Sanctioned admin work running the same command must score lower."""
        provider = HeuristicProvider()
        attack = provider.score_alert(
            {
                "severity": "critical",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "parent_name": "lb3.exe",
                "tactic": "impact",
            }
        )
        backup = provider.score_alert(
            {
                "severity": "critical",
                "command_line": "vssadmin.exe delete shadows /for=D: /oldest /quiet",
                "parent_name": "veeamagent.exe",
                "user": "svc_backup",
                "tactic": "impact",
            }
        )
        assert backup["risk_score"] < attack["risk_score"]

    def test_reasoning_is_always_populated(self, result):
        for alert in result.alerts:
            assert alert.triage["reasoning"]

    def test_empty_alert_list_is_handled(self):
        assert AlertTriageAgent(provider=HeuristicProvider()).triage([]) == []


class TestRuleAuthoring:
    def test_drafts_are_produced_for_gaps(self, result):
        assert result.proposed_rules

    def test_drafts_are_never_auto_enabled(self, result):
        """Automated detection engineering assists review; it does not bypass it."""
        assert all(not r.enabled for r in result.proposed_rules)

    def test_drafts_are_syntactically_valid(self, result):
        assert DetectionEngine(result.proposed_rules).validate() == []

    def test_drafts_are_attributed_to_the_ai_source(self, result):
        assert all(r.source.startswith("ai:") for r in result.proposed_rules)

    def test_overly_broad_candidate_is_rejected(self, scenarios):
        """A rule matching everything achieves perfect recall and is worthless."""
        author = DetectionAuthor(provider=HeuristicProvider())
        events = TelemetryEmitter(seed=4).emit(scenarios[0])
        catch_all = DetectionRule(
            rule_id="BROAD",
            title="matches everything",
            description="",
            severity=Severity.HIGH,
            techniques=[TechniqueRef("T1059.001", "PowerShell", "execution")],
            detection={"sel": {"user|exists": True}},
            condition="sel",
        )
        malicious = [e for e in events if e.technique_id == "T1059.001"]
        verdict = author._validate(catch_all, malicious, events, [])
        assert not verdict["accepted"]
        assert "too broad" in verdict["reason"]

    def test_duplicate_candidate_is_rejected(self, scenarios, rules):
        author = DetectionAuthor(provider=HeuristicProvider())
        events = TelemetryEmitter(seed=4).emit(scenarios[0])
        existing = next(r for r in rules if r.rule_id == "PF-R-0003")
        clone = DetectionRule(
            rule_id="CLONE",
            title="clone",
            description="",
            severity=existing.severity,
            techniques=existing.techniques,
            detection=existing.detection,
            condition=existing.condition,
        )
        malicious = [e for e in events if e.is_malicious]
        verdict = author._validate(clone, malicious, events, [existing])
        assert not verdict["accepted"]

    def test_drafts_write_as_disabled_yaml(self, result, tmp_path):
        import yaml

        written = DetectionAuthor.write(result.proposed_rules[:2], tmp_path)
        assert written
        for path in written:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            assert payload["enabled"] is False


class TestHoldoutEvaluation:
    def test_holdout_is_reported(self, result):
        assert "holdout" in result.improvement

    def test_holdout_uses_a_different_seed(self, result):
        assert result.improvement["holdout"]["seed"] != 1337

    def test_ai_rules_improve_recall_on_holdout(self, result):
        assert result.improvement["holdout"]["delta"]["techniques_recovered"] > 0

    def test_holdout_does_not_exceed_in_sample_recovery(self, result):
        """Holdout is the conservative measure; it must never flatter the result."""
        holdout = result.improvement["holdout"]["delta"]["techniques_recovered"]
        in_sample = result.improvement["delta"]["techniques_recovered"]
        assert holdout <= in_sample

    def test_overfit_rules_are_identified(self, result):
        """The honest-reporting property.

        Any technique recovered in-sample but missed on holdout must be named, not
        folded into the headline number.
        """
        holdout = result.improvement["holdout"]
        assert holdout["overfit_count"] == len(holdout["in_sample_only"])
        assert set(holdout["in_sample_only"]).isdisjoint(holdout["generalised"])


class TestAdvancedPipelineOutputs:
    def test_attack_path_reports_adaptive_route_change_and_safe_timing_metadata(self, result):
        paths = result.attack_paths
        assert paths["route_changed"] is True
        assert paths["baseline"]["hosts"] != paths["adaptive"]["hosts"]
        assert paths["feedback"]["host"] == "BUILD-01"
        timing = paths["adaptive"]["metadata"]["timing_dilation"]
        assert timing["metadata_only"] is True
        assert timing["exceeds_window"] is True
        assert "No commands" in paths["safety"]

    def test_incident_output_reports_lossless_alert_compression(self, result):
        incidents = result.incidents
        assert incidents["alert_count"] == len(result.alerts)
        assert incidents["incident_count"] == len(incidents["incidents"])
        assert sum(item["alert_count"] for item in incidents["incidents"]) == len(result.alerts)
        assert incidents["compression_ratio"] == pytest.approx(
            round(incidents["alert_count"] / incidents["incident_count"], 2)
        )
        assert incidents["compression_ratio"] >= 1
        assert all(item["evidence_lineage"] for item in incidents["incidents"])

    def test_behavioral_metrics_are_bounded_and_internally_consistent(self, result):
        behavioral = result.behavioral
        assert 0 <= behavioral["precision"] <= 1
        assert 0 <= behavioral["event_recall"] <= 1
        assert behavioral["anomalous_events"] == (
            behavioral["true_positive_events"] + behavioral["false_positive_events"]
        )
        assert behavioral["true_positive_events"] <= behavioral["malicious_events"]
        expected_precision = (
            behavioral["true_positive_events"] / behavioral["anomalous_events"]
            if behavioral["anomalous_events"] else 0
        )
        expected_recall = (
            behavioral["true_positive_events"] / behavioral["malicious_events"]
            if behavioral["malicious_events"] else 0
        )
        assert behavioral["precision"] == pytest.approx(round(expected_precision, 4))
        assert behavioral["event_recall"] == pytest.approx(round(expected_recall, 4))
        assert "score-only" in behavioral["protocol"]

    def test_advanced_outputs_are_serialized(self, result):
        payload = result.to_dict()
        assert payload["attack_paths"] == result.attack_paths
        assert payload["incidents"] == result.incidents
        assert payload["behavioral"] == result.behavioral
