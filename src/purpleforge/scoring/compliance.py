"""Control framework mapping.

Detection coverage is an engineering metric. Audit and risk functions work in
control frameworks. Translating between them is normally a manual spreadsheet
exercise repeated every audit cycle, and it is usually asserted rather than
evidenced: a control is marked implemented because a tool is licensed, not because
anyone demonstrated it detects the technique it claims to cover.

This module derives control status from measured detection outcomes. A control is
only 'effective' when the techniques mapped to it were actually detected during
emulation, so the output is evidence rather than assertion.

Mappings are drawn from the published crosswalks:

* MITRE ATT&CK to NIST SP 800-53 Rev 5 (MITRE Engenuity Center for Threat-Informed
  Defense, "Mappings Explorer")
* NIST Cybersecurity Framework 2.0 functions and categories
* ISO/IEC 27001:2022 Annex A controls

The mapping is a curated subset covering the techniques bundled here, not the full
crosswalk. That bound is stated in the report output, because a compliance artifact
that overstates its own scope is worse than no artifact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from purpleforge.scoring.scorecard import Scorecard


@dataclass(frozen=True)
class Control:
    """One control from a framework, with the techniques it is expected to address."""

    control_id: str
    framework: str
    title: str
    techniques: frozenset[str]

    def __post_init__(self) -> None:
        if not self.techniques:
            raise ValueError(f"{self.control_id}: a control with no techniques is untestable")


# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev 5
# ---------------------------------------------------------------------------
_NIST_800_53: list[Control] = [
    Control("AC-2", "NIST SP 800-53", "Account Management",
            frozenset({"T1087.002", "T1134.001"})),
    Control("AC-3", "NIST SP 800-53", "Access Enforcement",
            frozenset({"T1134.001", "T1021.002"})),
    Control("AC-17", "NIST SP 800-53", "Remote Access",
            frozenset({"T1133", "T1021.002"})),
    Control("AU-6", "NIST SP 800-53", "Audit Record Review, Analysis, and Reporting",
            frozenset({"T1562.001", "T1213"})),
    Control("CM-7", "NIST SP 800-53", "Least Functionality",
            frozenset({"T1059.001", "T1546.003", "T1560.001"})),
    Control("CP-9", "NIST SP 800-53", "System Backup",
            frozenset({"T1490", "T1486"})),
    Control("CP-10", "NIST SP 800-53", "System Recovery and Reconstitution",
            frozenset({"T1490"})),
    Control("IA-5", "NIST SP 800-53", "Authenticator Management",
            frozenset({"T1003.001", "T1110.001"})),
    Control("SC-7", "NIST SP 800-53", "Boundary Protection",
            frozenset({"T1041", "T1567.002", "T1046"})),
    Control("SI-3", "NIST SP 800-53", "Malicious Code Protection",
            frozenset({"T1566.001", "T1059.001", "T1486", "T1562.001"})),
    Control("SI-4", "NIST SP 800-53", "System Monitoring",
            frozenset({"T1046", "T1087.002", "T1021.002", "T1213.003"})),
    Control("MP-7", "NIST SP 800-53", "Media Use",
            frozenset({"T1052.001"})),
]

# ---------------------------------------------------------------------------
# NIST Cybersecurity Framework 2.0
# ---------------------------------------------------------------------------
_NIST_CSF: list[Control] = [
    Control("ID.RA-01", "NIST CSF 2.0", "Vulnerabilities in assets are identified",
            frozenset({"T1046", "T1133"})),
    Control("PR.AA-05", "NIST CSF 2.0", "Access permissions enforce least privilege",
            frozenset({"T1134.001", "T1087.002"})),
    Control("PR.DS-01", "NIST CSF 2.0", "Confidentiality of data-at-rest is protected",
            frozenset({"T1213", "T1213.003", "T1486"})),
    Control("PR.DS-02", "NIST CSF 2.0", "Confidentiality of data-in-transit is protected",
            frozenset({"T1041", "T1567.002", "T1052.001"})),
    Control("PR.PS-01", "NIST CSF 2.0", "Configuration management practices are established",
            frozenset({"T1562.001", "T1546.003"})),
    Control("DE.CM-01", "NIST CSF 2.0", "Networks are monitored to find adverse events",
            frozenset({"T1046", "T1041", "T1021.002"})),
    Control("DE.CM-03", "NIST CSF 2.0", "Personnel activity is monitored for adverse events",
            frozenset({"T1213.003", "T1052.001", "T1567.002"})),
    Control("DE.CM-09", "NIST CSF 2.0", "Computing hardware and software are monitored",
            frozenset({"T1059.001", "T1003.001", "T1566.001", "T1560.001"})),
    Control("DE.AE-02", "NIST CSF 2.0", "Adverse events are analysed to understand attack targets",
            frozenset({"T1134.001", "T1490"})),
    Control("RC.RP-01", "NIST CSF 2.0", "Recovery portion of the response plan is executed",
            frozenset({"T1490", "T1486"})),
]

# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A
# ---------------------------------------------------------------------------
_ISO_27001: list[Control] = [
    Control("A.5.15", "ISO/IEC 27001:2022", "Access control",
            frozenset({"T1134.001", "T1087.002", "T1021.002"})),
    Control("A.5.17", "ISO/IEC 27001:2022", "Authentication information",
            frozenset({"T1003.001", "T1110.001"})),
    Control("A.6.8", "ISO/IEC 27001:2022", "Information security event reporting",
            frozenset({"T1562.001"})),
    Control("A.7.10", "ISO/IEC 27001:2022", "Storage media",
            frozenset({"T1052.001"})),
    Control("A.8.7", "ISO/IEC 27001:2022", "Protection against malware",
            frozenset({"T1566.001", "T1059.001", "T1486"})),
    Control("A.8.12", "ISO/IEC 27001:2022", "Data leakage prevention",
            frozenset({"T1041", "T1567.002", "T1213", "T1213.003", "T1560.001"})),
    Control("A.8.13", "ISO/IEC 27001:2022", "Information backup",
            frozenset({"T1490", "T1486"})),
    Control("A.8.16", "ISO/IEC 27001:2022", "Monitoring activities",
            frozenset({"T1046", "T1021.002", "T1134.001"})),
    Control("A.8.20", "ISO/IEC 27001:2022", "Networks security",
            frozenset({"T1133", "T1046", "T1041"})),
    Control("A.8.21", "ISO/IEC 27001:2022", "Security of network services",
            frozenset({"T1133", "T1021.002"})),
]

FRAMEWORKS: dict[str, list[Control]] = {
    "NIST SP 800-53": _NIST_800_53,
    "NIST CSF 2.0": _NIST_CSF,
    "ISO/IEC 27001:2022": _ISO_27001,
}


@dataclass
class ControlAssessment:
    """Measured status of one control."""

    control: Control
    techniques_in_scope: list[str]
    techniques_detected: list[str]

    @property
    def coverage(self) -> float:
        if not self.techniques_in_scope:
            return 0.0
        return len(self.techniques_detected) / len(self.techniques_in_scope)

    @property
    def status(self) -> str:
        """Control effectiveness, derived from detection outcomes.

        ``not_assessed`` is distinct from ``ineffective`` on purpose. A control
        whose techniques were never emulated has no evidence either way, and
        collapsing that into a failure would be as misleading as calling it a pass.
        """
        if not self.techniques_in_scope:
            return "not_assessed"
        if self.coverage == 1.0:
            return "effective"
        if self.coverage > 0.0:
            return "partially_effective"
        return "ineffective"

    @property
    def gaps(self) -> list[str]:
        return sorted(set(self.techniques_in_scope) - set(self.techniques_detected))

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control.control_id,
            "framework": self.control.framework,
            "title": self.control.title,
            "status": self.status,
            "coverage": round(self.coverage, 3),
            "techniques_in_scope": sorted(self.techniques_in_scope),
            "techniques_detected": sorted(self.techniques_detected),
            "techniques_not_detected": self.gaps,
        }


@dataclass
class ComplianceReport:
    """Control status across every mapped framework."""

    assessments: list[ControlAssessment]
    techniques_emulated: list[str]
    unmapped_techniques: list[str] = field(default_factory=list)

    def by_framework(self) -> dict[str, dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}

        for assessment in self.assessments:
            bucket = grouped.setdefault(
                assessment.control.framework,
                {"effective": 0, "partially_effective": 0, "ineffective": 0,
                 "not_assessed": 0, "controls": []},
            )
            bucket[assessment.status] += 1
            bucket["controls"].append(assessment.to_dict())

        for bucket in grouped.values():
            assessed = (
                bucket["effective"] + bucket["partially_effective"] + bucket["ineffective"]
            )
            bucket["assessed_controls"] = assessed
            # Partial credit is counted as half. Stated explicitly because any
            # single number here hides a scoring choice, and an auditor is
            # entitled to know which one was made.
            bucket["weighted_coverage"] = (
                round((bucket["effective"] + 0.5 * bucket["partially_effective"]) / assessed, 3)
                if assessed
                else 0.0
            )

        return grouped

    @property
    def ineffective_controls(self) -> list[ControlAssessment]:
        """Controls with zero detection evidence. The remediation queue."""
        return [a for a in self.assessments if a.status == "ineffective"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_note": (
                "Control status is derived from detection outcomes during adversary "
                "emulation. A control is marked effective only where every mapped "
                "technique was detected. Mappings cover the techniques emulated here, "
                "not the complete framework crosswalk, so absence of a control from "
                "this report is not evidence about that control."
            ),
            "techniques_emulated": sorted(self.techniques_emulated),
            "unmapped_techniques": sorted(self.unmapped_techniques),
            "frameworks": self.by_framework(),
            "remediation_queue": [a.to_dict() for a in self.ineffective_controls],
        }


def build_compliance_report(scorecard: Scorecard) -> ComplianceReport:
    """Derive control status from a coverage scorecard."""
    emulated = {c.technique.technique_id for c in scorecard.coverage}
    detected = scorecard.detected_technique_ids

    assessments: list[ControlAssessment] = []
    mapped: set[str] = set()

    for controls in FRAMEWORKS.values():
        for control in controls:
            mapped.update(control.techniques)
            # Only techniques actually emulated are in scope. Claiming a status
            # for an untested technique would be an assertion, not evidence.
            in_scope = sorted(control.techniques & emulated)
            assessments.append(
                ControlAssessment(
                    control=control,
                    techniques_in_scope=in_scope,
                    techniques_detected=sorted(set(in_scope) & detected),
                )
            )

    return ComplianceReport(
        assessments=assessments,
        techniques_emulated=sorted(emulated),
        unmapped_techniques=sorted(emulated - mapped),
    )
