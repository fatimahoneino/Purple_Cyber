"""Tests for behavioral baselines and deterministic incident reconstruction."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import pytest

from purpleforge.defensive import (
    BehavioralBaseline,
    FeatureBaseline,
    IncidentReconstructor,
    RunningStats,
)
from purpleforge.models import Alert, Event, Severity

BASE = datetime(2025, 1, 1, tzinfo=timezone.utc)


def event(offset: int, *, host: str = "H1", user: str = "alice", malicious: bool = False, event_id: str = "", **fields) -> Event:
    return Event(
        timestamp=BASE + timedelta(seconds=offset), source="sysmon", event_type="process_creation",
        host=host, user=user, fields=fields,
        labels={"technique_id": "T1059.001"} if malicious else {}, event_id=event_id,
    )


def alert(
    alert_id: str, offset: int, *, host: str = "H1", user: str = "alice",
    matched_offset: int = 0, malicious: bool = False, rule_id: str | None = None,
    event_id: str = "", risk: float | None = None,
) -> Alert:
    triage = {"risk_score": risk} if risk is not None else None
    return Alert(
        alert_id=alert_id, rule_id=rule_id or f"rule-{alert_id}", rule_title=alert_id,
        severity=Severity.HIGH,
        event=event(offset, host=host, user=user, malicious=malicious, event_id=event_id),
        matched_at=BASE + timedelta(seconds=matched_offset), techniques=["T1059.001"], triage=triage,
    )


class TestRunningStatistics:
    def test_welford_matches_known_sample_statistics(self):
        stats = RunningStats()
        for value in [2, 4, 4, 4, 5, 5, 7, 9]:
            stats.update(value)
        assert stats.count == 8
        assert stats.mean == pytest.approx(5)
        assert stats.variance == pytest.approx(32 / 7)
        assert stats.standard_deviation == pytest.approx(math.sqrt(32 / 7))

    def test_welford_is_stable_for_large_offsets_and_ignores_nonfinite_values(self):
        stats = RunningStats()
        for value in [1_000_000_000_001, 1_000_000_000_002, float("nan"), float("inf"), 1_000_000_000_003]:
            stats.update(value)
        assert stats.count == 3
        assert stats.mean == pytest.approx(1_000_000_000_002)
        assert stats.variance == pytest.approx(1)

    def test_median_mad_scoring_resists_outlier(self):
        baseline = FeatureBaseline()
        for value in [10, 10, 11, 9, 10, 1000]:
            baseline.update(value)
        score, method, center, scale = baseline.score(13, min_samples=5)
        assert method == "median_mad"
        assert center == 10
        assert baseline.mad == pytest.approx(0.5)
        assert scale == pytest.approx(0.7413)
        assert score == pytest.approx(3 / 0.7413)

    def test_zero_variance_is_safe_and_marks_only_changes(self):
        baseline = FeatureBaseline()
        for _ in range(5):
            baseline.update(7)
        same = baseline.score(7, min_samples=5)
        changed = baseline.score(8, min_samples=5)
        assert same[:2] == (0.0, "zero_variance")
        assert math.isinf(changed[0])
        assert changed[1:] == ("zero_variance", 7, 0.0)


class TestBehavioralBaseline:
    def test_fit_then_score_does_not_poison_baseline(self):
        model = BehavioralBaseline(min_samples=3, threshold=3, robust_window=5)
        model.fit([event(i, metric=10) for i in range(3)])
        before = model.snapshot()["host:H1|user:alice"]["metric"]
        findings = model.score_event(event(10, metric=999))
        after = model.snapshot()["host:H1|user:alice"]["metric"]
        assert any(f.feature == "metric" and f.is_anomaly for f in findings)
        assert after.count == before.count == 3
        assert after.stats.mean == before.stats.mean == 10
        assert after.median == before.median == 10

    def test_observe_scores_before_learning_then_updates(self):
        model = BehavioralBaseline(min_samples=3, threshold=3, robust_window=5)
        model.fit([event(i, metric=10) for i in range(3)])
        findings = model.observe(event(10, metric=999))
        baseline = model.snapshot()["host:H1|user:alice"]["metric"]
        assert any(f.feature == "metric" and math.isinf(f.score) for f in findings)
        assert baseline.count == 4
        assert baseline.stats.mean > 10

    def test_new_feature_is_not_novel_before_entity_maturity(self):
        model = BehavioralBaseline(min_samples=3, threshold=3)
        model.fit([event(0, known=1), event(1, known=1)])
        findings = model.score_event(event(2, known=1, novel=9))
        assert not any(f.feature == "novel" for f in findings)

    def test_new_feature_is_novel_only_after_entity_maturity(self):
        model = BehavioralBaseline(min_samples=3, threshold=3)
        model.fit([event(i, known=1) for i in range(3)])
        findings = model.score_event(event(3, known=1, novel=9))
        novelty = [f for f in findings if f.feature == "novel"]
        assert len(novelty) == 1
        assert novelty[0].method == "feature_novelty"
        assert novelty[0].sample_count == 3
        assert math.isinf(novelty[0].score)


class TestIncidentReconstruction:
    def test_window_uses_event_timestamp_not_matched_at(self):
        alerts = [
            alert("a", 0, matched_offset=10_000),
            alert("b", 120, matched_offset=20_000),
            alert("c", 1_000, matched_offset=10_001),
        ]
        incidents = IncidentReconstructor(window=timedelta(minutes=5)).reconstruct(alerts)
        assert {item.alert_ids for item in incidents} == {("a", "b"), ("c",)}
        joined = next(item for item in incidents if len(item.alerts) == 2)
        assert joined.started_at == BASE
        assert joined.ended_at == BASE + timedelta(seconds=120)

    def test_cross_entity_alerts_remain_isolated(self):
        alerts = [
            alert("a", 0, host="H1", user="alice"),
            alert("b", 1, host="H2", user="bob"),
        ]
        incidents = IncidentReconstructor().reconstruct(alerts)
        assert len(incidents) == 2
        assert {item.entities for item in incidents} == {
            ("host:h1", "user:alice"), ("host:h2", "user:bob")
        }

    def test_duplicate_evidence_does_not_inflate_risk(self):
        single = alert("a", 0, rule_id="same", event_id="evidence", risk=80)
        duplicate = alert("b", 0, rule_id="same", event_id="evidence", risk=80)
        unique = alert("c", 1, rule_id="other", event_id="other-evidence", risk=50)
        reconstructor = IncidentReconstructor()
        base_risk = reconstructor.reconstruct([single, unique])[0].risk_score
        duplicate_risk = reconstructor.reconstruct([single, duplicate, unique])[0].risk_score
        assert base_risk == duplicate_risk == 90

    def test_ids_and_membership_are_deterministic_across_input_order(self):
        alerts = [alert("a", 2), alert("b", 1), alert("c", 9000, host="H2", user="bob")]
        first = IncidentReconstructor().reconstruct(alerts)
        second = IncidentReconstructor().reconstruct(reversed(alerts))
        assert [(item.incident_id, item.alert_ids) for item in first] == [
            (item.incident_id, item.alert_ids) for item in second
        ]
        assert all(item.incident_id.startswith("inc-") and len(item.incident_id) == 20 for item in first)

    def test_ground_truth_does_not_affect_ids_risk_confidence_or_ranking(self):
        benign = [
            alert("high", 0, host="H1", user="alice", malicious=False, risk=90),
            alert("low", 0, host="H2", user="bob", malicious=False, risk=20),
        ]
        labelled = [
            alert("high", 0, host="H1", user="alice", malicious=True, risk=90),
            alert("low", 0, host="H2", user="bob", malicious=True, risk=20),
        ]
        before = IncidentReconstructor().reconstruct(benign)
        after = IncidentReconstructor().reconstruct(labelled)
        operational = lambda items: [
            (item.incident_id, item.alert_ids, item.risk_score, item.confidence, item.entities)
            for item in items
        ]
        assert operational(before) == operational(after)
        assert [item.alert_ids for item in after] == [("high",), ("low",)]
        assert [item.purity for item in before] == [0, 0]
        assert [item.purity for item in after] == [1, 1]
