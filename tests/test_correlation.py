"""Correlation engine tests.

Stateful detection has failure modes single-event matching does not: unbounded
windows, cross-entity correlation, and duplicate alerts for one finding. Each is
covered here because all three produce impressive-looking recall while being
operationally useless.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from purpleforge.detection.correlation import (
    CorrelationEngine,
    CorrelationRule,
    CorrelationStage,
)
from purpleforge.detection.correlation_loader import (
    load_all_correlation_rules,
    load_correlation_rule,
)
from purpleforge.detection.engine import RuleSyntaxError
from purpleforge.models import Event, Severity, TechniqueRef, utcnow

BASE = utcnow()


def event(offset_seconds: int, host: str = "H1", user: str = "alice", **fields) -> Event:
    labels = {}
    if "technique_id" in fields:
        labels["technique_id"] = fields.pop("technique_id")
    return Event(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source="sysmon",
        event_type=fields.pop("event_type", "process_creation"),
        host=host,
        user=user,
        fields=fields,
        labels=labels,
    )


def sequence_rule(window: int = 600, group_by: str = "host") -> CorrelationRule:
    return CorrelationRule(
        rule_id="SEQ-1",
        title="stage A then B",
        description="",
        severity=Severity.HIGH,
        correlation_type="sequence",
        window_seconds=window,
        group_by=group_by,
        techniques=[TechniqueRef("T1134.001", "Token Theft", "privilege-escalation")],
        stages=[
            CorrelationStage("first", {"process.name": "a.exe"}),
            CorrelationStage("second", {"process.name": "b.exe"}),
        ],
    )


class TestRuleValidation:
    def test_sequence_needs_two_stages(self):
        with pytest.raises(RuleSyntaxError, match="at least 2 stages"):
            CorrelationRule(
                rule_id="R", title="t", description="", severity=Severity.HIGH,
                correlation_type="sequence", window_seconds=60,
                stages=[CorrelationStage("only", {"a": 1})],
            )

    def test_unbounded_window_is_rejected(self):
        """An unbounded window eventually matches anything."""
        with pytest.raises(RuleSyntaxError, match="window_seconds must be positive"):
            CorrelationRule(
                rule_id="R", title="t", description="", severity=Severity.HIGH,
                correlation_type="threshold", window_seconds=0,
                selection={"a": 1}, threshold=5,
            )

    def test_threshold_of_one_is_rejected(self):
        """Threshold 1 is a single-event rule wearing a correlation costume."""
        with pytest.raises(RuleSyntaxError, match="threshold must be at least 2"):
            CorrelationRule(
                rule_id="R", title="t", description="", severity=Severity.HIGH,
                correlation_type="threshold", window_seconds=60,
                selection={"a": 1}, threshold=1,
            )

    def test_unknown_type_is_rejected(self):
        with pytest.raises(RuleSyntaxError, match="correlation type must be"):
            CorrelationRule(
                rule_id="R", title="t", description="", severity=Severity.HIGH,
                correlation_type="magic", window_seconds=60, selection={"a": 1}, threshold=2,
            )

    def test_distinct_requires_a_field(self):
        with pytest.raises(RuleSyntaxError, match="distinct_field"):
            CorrelationRule(
                rule_id="R", title="t", description="", severity=Severity.HIGH,
                correlation_type="distinct", window_seconds=60,
                selection={"a": 1}, threshold=3,
            )


class TestSequence:
    def test_fires_on_ordered_stages_in_window(self):
        events = [event(0, **{"process.name": "a.exe"}), event(60, **{"process.name": "b.exe"})]
        alerts = CorrelationEngine([sequence_rule()]).run(events)
        assert len(alerts) == 1
        assert alerts[0].is_correlation
        assert len(alerts[0].all_events) == 2

    def test_does_not_fire_when_order_reversed(self):
        """Sequence order is the whole point; B-then-A is not the pattern."""
        events = [event(0, **{"process.name": "b.exe"}), event(60, **{"process.name": "a.exe"})]
        assert CorrelationEngine([sequence_rule()]).run(events) == []

    def test_does_not_fire_outside_window(self):
        events = [event(0, **{"process.name": "a.exe"}), event(9999, **{"process.name": "b.exe"})]
        assert CorrelationEngine([sequence_rule(window=600)]).run(events) == []

    def test_does_not_correlate_across_different_hosts(self):
        """Without group_by isolation, unrelated hosts form phantom intrusions."""
        events = [
            event(0, host="H1", **{"process.name": "a.exe"}),
            event(60, host="H2", **{"process.name": "b.exe"}),
        ]
        assert CorrelationEngine([sequence_rule(group_by="host")]).run(events) == []

    def test_group_by_user_correlates_across_hosts(self):
        events = [
            event(0, host="H1", user="bob", **{"process.name": "a.exe"}),
            event(60, host="H2", user="bob", **{"process.name": "b.exe"}),
        ]
        assert len(CorrelationEngine([sequence_rule(group_by="user")]).run(events)) == 1

    def test_events_are_not_reused_across_alerts(self):
        """One completion consumes its events, so two chains need four events."""
        events = [
            event(0, **{"process.name": "a.exe"}),
            event(10, **{"process.name": "b.exe"}),
            event(20, **{"process.name": "a.exe"}),
            event(30, **{"process.name": "b.exe"}),
        ]
        alerts = CorrelationEngine([sequence_rule()]).run(events)
        assert len(alerts) == 2
        ids = [e.event_id for a in alerts for e in a.all_events]
        assert len(ids) == len(set(ids))

    def test_single_a_with_no_b_does_not_fire(self):
        events = [event(0, **{"process.name": "a.exe"})] * 1
        assert CorrelationEngine([sequence_rule()]).run(events) == []

    def test_stage_exclude_vetoes_a_match(self):
        rule = CorrelationRule(
            rule_id="SEQ-X", title="t", description="", severity=Severity.HIGH,
            correlation_type="sequence", window_seconds=600,
            stages=[
                CorrelationStage("first", {"process.name": "a.exe"}),
                CorrelationStage(
                    "second",
                    {"process.name": "b.exe"},
                    exclude={"process.parent_name": "trusted.exe"},
                ),
            ],
        )
        vetoed = [
            event(0, **{"process.name": "a.exe"}),
            event(60, **{"process.name": "b.exe", "process.parent_name": "trusted.exe"}),
        ]
        allowed = [
            event(0, **{"process.name": "a.exe"}),
            event(60, **{"process.name": "b.exe", "process.parent_name": "other.exe"}),
        ]
        engine = CorrelationEngine([rule])
        assert engine.run(vetoed) == []
        assert len(engine.run(allowed)) == 1


class TestThreshold:
    def _rule(self, threshold: int = 3, window: int = 300) -> CorrelationRule:
        return CorrelationRule(
            rule_id="THR-1", title="failures", description="", severity=Severity.MEDIUM,
            correlation_type="threshold", window_seconds=window,
            selection={"auth.result": "failure"}, threshold=threshold,
        )

    def test_fires_at_threshold(self):
        events = [event(i * 10, **{"auth.result": "failure"}) for i in range(3)]
        assert len(CorrelationEngine([self._rule()]).run(events)) == 1

    def test_does_not_fire_below_threshold(self):
        events = [event(i * 10, **{"auth.result": "failure"}) for i in range(2)]
        assert CorrelationEngine([self._rule()]).run(events) == []

    def test_does_not_fire_when_spread_beyond_window(self):
        events = [event(i * 1000, **{"auth.result": "failure"}) for i in range(3)]
        assert CorrelationEngine([self._rule(window=300)]).run(events) == []

    def test_one_alert_per_window_not_per_event(self):
        """Six matches in one window is one finding, not four duplicate alerts."""
        events = [event(i * 5, **{"auth.result": "failure"}) for i in range(6)]
        alerts = CorrelationEngine([self._rule(threshold=3)]).run(events)
        assert len(alerts) == 2  # 6 events / threshold 3

    def test_non_matching_events_are_ignored(self):
        events = [event(i * 10, **{"auth.result": "success"}) for i in range(9)]
        assert CorrelationEngine([self._rule()]).run(events) == []


class TestDistinct:
    def _rule(self, threshold: int = 3) -> CorrelationRule:
        return CorrelationRule(
            rule_id="DIS-1", title="sweep", description="", severity=Severity.MEDIUM,
            correlation_type="distinct", window_seconds=600,
            selection={"event_type": "network_connection"},
            threshold=threshold, distinct_field="destination.ip",
        )

    def test_fires_on_distinct_destinations(self):
        events = [
            event(i * 10, event_type="network_connection", **{"destination.ip": f"10.0.0.{i}"})
            for i in range(3)
        ]
        assert len(CorrelationEngine([self._rule()]).run(events)) == 1

    def test_repeated_same_destination_does_not_fire(self):
        """The key distinction from a plain threshold: retries are not a sweep.

        A misconfigured client hammering one host produces high volume and low
        distinct count. Counting raw events would flag it as reconnaissance.
        """
        events = [
            event(i * 10, event_type="network_connection", **{"destination.ip": "10.0.0.5"})
            for i in range(20)
        ]
        assert CorrelationEngine([self._rule()]).run(events) == []


class TestGroundTruth:
    def test_correlation_of_malicious_events_is_a_true_positive(self):
        events = [
            event(0, technique_id="T1134.001", **{"process.name": "a.exe"}),
            event(60, technique_id="T1134.001", **{"process.name": "b.exe"}),
        ]
        alert = CorrelationEngine([sequence_rule()]).run(events)[0]
        assert alert.is_true_positive
        assert alert.correlation_purity == 1.0

    def test_correlation_of_benign_events_is_a_false_positive(self):
        """A chain assembled from benign events is noise however long it is."""
        events = [event(0, **{"process.name": "a.exe"}), event(60, **{"process.name": "b.exe"})]
        alert = CorrelationEngine([sequence_rule()]).run(events)[0]
        assert not alert.is_true_positive
        assert alert.correlation_purity == 0.0

    def test_purity_reports_partially_noisy_chains(self):
        """A technically-true-positive chain can still be mostly noise."""
        events = [
            event(0, technique_id="T1134.001", **{"process.name": "a.exe"}),
            event(60, **{"process.name": "b.exe"}),
        ]
        alert = CorrelationEngine([sequence_rule()]).run(events)[0]
        assert alert.is_true_positive
        assert alert.correlation_purity == 0.5

    def test_wrong_technique_claim_is_not_credited(self):
        rule = sequence_rule()
        rule.techniques = [TechniqueRef("T1486", "Encrypt", "impact")]
        events = [
            event(0, technique_id="T1134.001", **{"process.name": "a.exe"}),
            event(60, technique_id="T1134.001", **{"process.name": "b.exe"}),
        ]
        assert not CorrelationEngine([rule]).run(events)[0].is_true_positive


class TestBundledCorrelationRules:
    def test_they_load(self):
        assert len(load_all_correlation_rules()) >= 4

    def test_they_are_valid(self):
        assert CorrelationEngine(load_all_correlation_rules()).validate() == []

    def test_each_documents_false_positives_and_techniques(self):
        for rule in load_all_correlation_rules():
            assert rule.false_positives, f"{rule.rule_id} documents no false positives"
            assert rule.techniques, f"{rule.rule_id} has no ATT&CK mapping"
            assert rule.description.strip(), f"{rule.rule_id} has no description"

    def test_windows_are_bounded_and_reasonable(self):
        for rule in load_all_correlation_rules():
            assert 0 < rule.window_seconds <= 86400, f"{rule.rule_id} window is implausible"

    def test_malformed_file_is_skipped_not_fatal(self, tmp_path, capsys):
        import yaml

        (tmp_path / "bad.yml").write_text(
            yaml.safe_dump({"id": "BAD", "title": "t", "correlation": {"type": "sequence"}}),
            encoding="utf-8",
        )
        assert load_all_correlation_rules(tmp_path) == []
        assert "skipping" in capsys.readouterr().out

    def test_missing_correlation_block_is_rejected(self, tmp_path):
        import yaml

        path = tmp_path / "x.yml"
        path.write_text(yaml.safe_dump({"id": "X", "title": "t"}), encoding="utf-8")
        with pytest.raises(ValueError, match="missing 'correlation' block"):
            load_correlation_rule(path)


class TestEngineIsolation:
    def test_broken_rule_does_not_stop_the_others(self):
        good = sequence_rule()
        bad = CorrelationRule(
            rule_id="BAD", title="t", description="", severity=Severity.HIGH,
            correlation_type="threshold", window_seconds=60,
            selection={"process.name|bogus": "x"}, threshold=2,
        )
        events = [event(0, **{"process.name": "a.exe"}), event(60, **{"process.name": "b.exe"})]
        engine = CorrelationEngine([bad, good])
        alerts = engine.run(events)
        assert [a.rule_id for a in alerts] == ["SEQ-1"]
        assert engine.errors and engine.errors[0]["rule_id"] == "BAD"

    def test_disabled_rules_do_not_fire(self):
        rule = sequence_rule()
        rule.enabled = False
        events = [event(0, **{"process.name": "a.exe"}), event(60, **{"process.name": "b.exe"})]
        assert CorrelationEngine([rule]).run(events) == []
