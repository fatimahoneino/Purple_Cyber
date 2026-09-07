"""Control framework mapping tests.

A compliance artifact that overstates its own scope is worse than none, so the
properties tested here are mostly about honesty: untested controls must not be
reported as passing, and control status must be derived from measurement rather
than asserted.
"""

from __future__ import annotations

import pytest

from purpleforge.models import TechniqueRef
from purpleforge.scoring.compliance import (
    FRAMEWORKS,
    Control,
    ControlAssessment,
    build_compliance_report,
)
from purpleforge.scoring.scorecard import CoverageScore, Scorecard


def scorecard(detected: set[str], emulated: set[str]) -> Scorecard:
    coverage = [
        CoverageScore(
            TechniqueRef(tid, tid, "execution"),
            events_generated=1,
            alerts_fired=1 if tid in detected else 0,
            true_positives=1 if tid in detected else 0,
        )
        for tid in sorted(emulated)
    ]
    return Scorecard(
        scenario_results=[],
        coverage=coverage,
        total_events=10,
        total_malicious_events=len(emulated),
        total_alerts=len(detected),
        true_positives=len(detected),
        false_positives=0,
    )


class TestControlDefinitions:
    def test_every_control_maps_at_least_one_technique(self):
        for controls in FRAMEWORKS.values():
            for control in controls:
                assert control.techniques

    def test_control_without_techniques_is_rejected(self):
        with pytest.raises(ValueError, match="untestable"):
            Control("X-1", "F", "t", frozenset())

    def test_control_ids_are_unique_within_a_framework(self):
        for name, controls in FRAMEWORKS.items():
            ids = [c.control_id for c in controls]
            assert len(ids) == len(set(ids)), f"duplicate control id in {name}"

    def test_three_frameworks_are_mapped(self):
        assert set(FRAMEWORKS) == {"NIST SP 800-53", "NIST CSF 2.0", "ISO/IEC 27001:2022"}


class TestControlAssessment:
    def _control(self) -> Control:
        return Control("AC-1", "F", "t", frozenset({"T1001", "T1002"}))

    def test_all_detected_is_effective(self):
        a = ControlAssessment(self._control(), ["T1001", "T1002"], ["T1001", "T1002"])
        assert a.status == "effective"
        assert a.coverage == 1.0

    def test_some_detected_is_partial(self):
        a = ControlAssessment(self._control(), ["T1001", "T1002"], ["T1001"])
        assert a.status == "partially_effective"
        assert a.gaps == ["T1002"]

    def test_none_detected_is_ineffective(self):
        a = ControlAssessment(self._control(), ["T1001", "T1002"], [])
        assert a.status == "ineffective"

    def test_untested_is_not_assessed_rather_than_failed(self):
        """A control with no evidence is not a failing control.

        Collapsing 'never tested' into 'ineffective' would be as misleading as
        reporting it as a pass.
        """
        a = ControlAssessment(self._control(), [], [])
        assert a.status == "not_assessed"
        assert a.coverage == 0.0


class TestComplianceReport:
    def test_detected_techniques_drive_effective_status(self):
        report = build_compliance_report(scorecard({"T1490"}, {"T1490"}))
        cp10 = next(a for a in report.assessments if a.control.control_id == "CP-10")
        assert cp10.status == "effective"

    def test_missed_techniques_drive_ineffective_status(self):
        report = build_compliance_report(scorecard(set(), {"T1490"}))
        cp10 = next(a for a in report.assessments if a.control.control_id == "CP-10")
        assert cp10.status == "ineffective"

    def test_unemulated_techniques_are_out_of_scope(self):
        """Only measured techniques count. Untested controls report no status."""
        report = build_compliance_report(scorecard(set(), {"T1490"}))
        mp7 = next(a for a in report.assessments if a.control.control_id == "MP-7")
        assert mp7.status == "not_assessed"
        assert mp7.techniques_in_scope == []

    def test_weighted_coverage_gives_partial_credit(self):
        report = build_compliance_report(scorecard({"T1490"}, {"T1490", "T1486"}))
        cp9 = next(a for a in report.assessments if a.control.control_id == "CP-9")
        assert cp9.status == "partially_effective"
        assert cp9.coverage == 0.5

    def test_weighted_coverage_is_bounded(self):
        report = build_compliance_report(scorecard({"T1490", "T1486"}, {"T1490", "T1486"}))
        for data in report.by_framework().values():
            assert 0.0 <= data["weighted_coverage"] <= 1.0

    def test_remediation_queue_lists_only_ineffective_controls(self):
        report = build_compliance_report(scorecard(set(), {"T1490", "T1486"}))
        payload = report.to_dict()
        assert payload["remediation_queue"]
        assert all(c["status"] == "ineffective" for c in payload["remediation_queue"])

    def test_scope_note_is_always_present(self):
        """The artifact must state its own limits."""
        payload = build_compliance_report(scorecard({"T1490"}, {"T1490"})).to_dict()
        assert "not the complete framework crosswalk" in payload["scope_note"]

    def test_unmapped_techniques_are_disclosed(self):
        report = build_compliance_report(scorecard(set(), {"T9999"}))
        assert "T9999" in report.to_dict()["unmapped_techniques"]

    def test_bundled_techniques_are_fully_mapped(self):
        """Every technique the scenarios emulate should map to some control.

        An unmapped technique means the emulation tests something the compliance
        report silently cannot speak to.
        """
        from purpleforge.emulation.scenario import load_all_scenarios

        emulated = {
            t.technique_id for s in load_all_scenarios() for t in s.techniques
        }
        report = build_compliance_report(scorecard(set(), emulated))
        assert report.unmapped_techniques == [], (
            f"unmapped techniques: {report.unmapped_techniques}"
        )
