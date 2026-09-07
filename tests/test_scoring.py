"""Scoring tests.

The scorecard is the product of this platform, so the properties that make it
trustworthy get asserted directly: a rule that catches the wrong technique is not
credited, and noise that trips a rule is counted against precision.
"""

from __future__ import annotations

from purpleforge.models import Alert, Event, Severity, TechniqueRef, utcnow
from purpleforge.scoring.scorecard import CoverageScore, Scorecard


def make_event(technique_id: str | None = None, **kwargs) -> Event:
    labels = {"technique_id": technique_id} if technique_id else {}
    return Event(
        timestamp=utcnow(),
        source="sysmon",
        event_type="process_creation",
        host=kwargs.get("host", "WKS-1"),
        user="alice",
        fields=kwargs.get("fields", {}),
        labels=labels,
    )


def make_alert(event: Event, techniques: list[str], rule_id: str = "R1") -> Alert:
    return Alert(
        alert_id="a1",
        rule_id=rule_id,
        rule_title="rule",
        severity=Severity.HIGH,
        event=event,
        matched_at=utcnow(),
        techniques=techniques,
    )


class TestGroundTruth:
    def test_alert_on_malicious_event_with_matching_technique_is_tp(self):
        alert = make_alert(make_event("T1059.001"), ["T1059.001"])
        assert alert.is_true_positive

    def test_alert_on_benign_event_is_fp(self):
        alert = make_alert(make_event(None), ["T1059.001"])
        assert not alert.is_true_positive

    def test_base_technique_matches_subtechnique(self):
        """A rule tagged T1059 should get credit for catching T1059.001."""
        alert = make_alert(make_event("T1059.001"), ["T1059"])
        assert alert.is_true_positive

    def test_right_event_wrong_technique_is_not_a_tp(self):
        """Catching real attack activity for the wrong reason is still noise.

        This is the property that stops a broad rule from inflating coverage: it
        fires on an attack event, but claims an unrelated technique, so it earns
        no credit for the technique that actually occurred.
        """
        alert = make_alert(make_event("T1003.001"), ["T1486"])
        assert not alert.is_true_positive

    def test_untagged_rule_gets_credit_on_malicious_event(self):
        alert = make_alert(make_event("T1003.001"), [])
        assert alert.is_true_positive


class TestCoverageScore:
    def _technique(self) -> TechniqueRef:
        return TechniqueRef("T1059.001", "PowerShell", "execution")

    def test_status_full(self):
        score = CoverageScore(self._technique(), events_generated=2, alerts_fired=2, true_positives=2)
        assert score.status == "full"
        assert score.detected

    def test_status_partial(self):
        score = CoverageScore(self._technique(), events_generated=3, alerts_fired=1, true_positives=1)
        assert score.status == "partial"
        assert score.detected

    def test_status_none(self):
        score = CoverageScore(self._technique(), events_generated=2, alerts_fired=0, true_positives=0)
        assert score.status == "none"
        assert not score.detected

    def test_alerts_fired_without_true_positives_is_still_a_gap(self):
        """Firing on the right event for the wrong reason leaves the gap open."""
        score = CoverageScore(self._technique(), events_generated=2, alerts_fired=5, true_positives=0)
        assert score.status == "none"


class TestScorecardMetrics:
    def _card(self, tp: int, fp: int, detected: int, total: int) -> Scorecard:
        coverage = []
        for i in range(total):
            coverage.append(
                CoverageScore(
                    TechniqueRef(f"T10{i:02d}", f"t{i}", "execution"),
                    events_generated=1,
                    alerts_fired=1 if i < detected else 0,
                    true_positives=1 if i < detected else 0,
                )
            )
        return Scorecard(
            scenario_results=[],
            coverage=coverage,
            total_events=100,
            total_malicious_events=total,
            total_alerts=tp + fp,
            true_positives=tp,
            false_positives=fp,
        )

    def test_precision(self):
        assert self._card(tp=8, fp=2, detected=4, total=8).precision == 0.8

    def test_technique_recall(self):
        assert self._card(tp=4, fp=0, detected=4, total=8).technique_recall == 0.5

    def test_f1_balances_both(self):
        # Perfect recall with terrible precision must not score well.
        card = self._card(tp=5, fp=95, detected=8, total=8)
        assert card.technique_recall == 1.0
        assert card.precision == 0.05
        assert card.f1_score < 0.15
        assert card.grade == "F"

    def test_no_alerts_scores_zero_not_divide_by_zero(self):
        card = self._card(tp=0, fp=0, detected=0, total=5)
        assert card.precision == 0.0
        assert card.f1_score == 0.0

    def test_grade_thresholds(self):
        assert self._card(tp=10, fp=0, detected=10, total=10).grade == "A"
        assert self._card(tp=1, fp=99, detected=1, total=10).grade == "F"

    def test_alerts_per_true_positive(self):
        assert self._card(tp=5, fp=45, detected=5, total=10).alert_volume_per_true_positive == 10.0

    def test_gaps_are_ordered_by_missed_event_volume(self):
        coverage = [
            CoverageScore(TechniqueRef("T1001", "a", "execution"), 1, 0, 0),
            CoverageScore(TechniqueRef("T1002", "b", "execution"), 9, 0, 0),
        ]
        card = Scorecard([], coverage, 10, 10, 0, 0, 0)
        assert [g.technique.technique_id for g in card.gaps] == ["T1002", "T1001"]

    def test_detected_technique_ids(self):
        card = self._card(tp=2, fp=0, detected=2, total=4)
        assert card.detected_technique_ids == {"T1000", "T1001"}
