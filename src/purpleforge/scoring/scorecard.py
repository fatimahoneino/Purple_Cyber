"""Detection coverage scoring.

This is the layer that makes the project purple rather than just red plus blue.
Red-side ground truth labels every synthetic event, so precision and recall can
be computed directly instead of estimated.

Two metrics matter most and they pull in opposite directions:

* **Technique recall** -- of the techniques red executed, how many did blue catch?
  Rewards broad coverage.
* **Precision** -- of the alerts blue raised, how many were real? Punishes rules
  that achieve recall by matching everything.

A rule set can trivially max out either one alone. Reporting them together, plus
an F1 blend, is what stops a scorecard from being gamed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from purpleforge.emulation.scenario import Scenario
from purpleforge.models import Alert, Event, ScenarioResult, Severity, TechniqueRef


@dataclass
class CoverageScore:
    """Per-technique detection outcome."""

    technique: TechniqueRef
    events_generated: int
    alerts_fired: int
    true_positives: int
    detecting_rules: list[str] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return self.true_positives > 0

    @property
    def status(self) -> str:
        """Coverage bucket used by the report and the AI gap prompt."""
        if not self.detected:
            return "none"
        if self.true_positives >= self.events_generated:
            return "full"
        return "partial"

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique.technique_id,
            "technique_name": self.technique.name,
            "tactic": self.technique.tactic,
            "attack_url": self.technique.url,
            "events_generated": self.events_generated,
            "alerts_fired": self.alerts_fired,
            "true_positives": self.true_positives,
            "detecting_rules": self.detecting_rules,
            "detected": self.detected,
            "status": self.status,
        }


@dataclass
class Scorecard:
    """Aggregate purple-team assessment across one or more scenarios."""

    scenario_results: list[ScenarioResult]
    coverage: list[CoverageScore]
    total_events: int
    total_malicious_events: int
    total_alerts: int
    true_positives: int
    false_positives: int

    # ---------- headline metrics ----------

    @property
    def techniques_total(self) -> int:
        return len(self.coverage)

    @property
    def techniques_detected(self) -> int:
        return sum(1 for c in self.coverage if c.detected)

    @property
    def technique_recall(self) -> float:
        """Share of executed techniques with at least one genuine detection."""
        if not self.coverage:
            return 0.0
        return self.techniques_detected / self.techniques_total

    @property
    def precision(self) -> float:
        """Share of alerts that were genuine. Low precision means analyst burnout."""
        if self.total_alerts == 0:
            return 0.0
        return self.true_positives / self.total_alerts

    @property
    def event_recall(self) -> float:
        """Share of malicious events that produced at least one true positive."""
        if self.total_malicious_events == 0:
            return 0.0
        detected_events = {
            a.event.event_id
            for r in self.scenario_results
            for a in r.alerts
            if a.is_true_positive
        }
        return min(len(detected_events) / self.total_malicious_events, 1.0)

    @property
    def f1_score(self) -> float:
        """Harmonic mean of precision and technique recall."""
        p, r = self.precision, self.technique_recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    @property
    def alert_volume_per_true_positive(self) -> float:
        """How many alerts an analyst reads per real finding. Lower is better."""
        if self.true_positives == 0:
            return float(self.total_alerts)
        return self.total_alerts / self.true_positives

    @property
    def grade(self) -> str:
        """Letter grade from the F1 blend, for at-a-glance reporting."""
        score = self.f1_score
        for threshold, letter in ((0.9, "A"), (0.8, "B"), (0.65, "C"), (0.5, "D")):
            if score >= threshold:
                return letter
        return "F"

    # ---------- breakdowns ----------

    @property
    def detected_technique_ids(self) -> set[str]:
        """Technique ids with at least one genuine detection."""
        return {c.technique.technique_id for c in self.coverage if c.detected}

    @property
    def gaps(self) -> list[CoverageScore]:
        """Undetected techniques, worst first. This is the AI layer's work queue."""
        return sorted(
            (c for c in self.coverage if not c.detected),
            key=lambda c: (-c.events_generated, c.technique.technique_id),
        )

    @property
    def partial_coverage(self) -> list[CoverageScore]:
        return [c for c in self.coverage if c.status == "partial"]

    def by_tactic(self) -> dict[str, dict[str, Any]]:
        """Coverage rolled up per ATT&CK tactic, in kill-chain order."""
        buckets: dict[str, dict[str, Any]] = {}
        for score in self.coverage:
            bucket = buckets.setdefault(
                score.technique.tactic,
                {"total": 0, "detected": 0, "techniques": []},
            )
            bucket["total"] += 1
            bucket["detected"] += int(score.detected)
            bucket["techniques"].append(score.technique.technique_id)
        for bucket in buckets.values():
            bucket["coverage"] = bucket["detected"] / bucket["total"] if bucket["total"] else 0.0
        return buckets

    def noisiest_rules(self, limit: int = 5) -> list[dict[str, Any]]:
        """Rules producing the most false positives -- the tuning backlog."""
        tally: dict[str, dict[str, Any]] = {}
        for result in self.scenario_results:
            for alert in result.alerts:
                entry = tally.setdefault(
                    alert.rule_id,
                    {"rule_id": alert.rule_id, "title": alert.rule_title, "fp": 0, "tp": 0},
                )
                if alert.is_true_positive:
                    entry["tp"] += 1
                else:
                    entry["fp"] += 1

        for entry in tally.values():
            total = entry["fp"] + entry["tp"]
            entry["fp_rate"] = entry["fp"] / total if total else 0.0

        ranked = sorted(tally.values(), key=lambda e: (-e["fp"], e["rule_id"]))
        return [e for e in ranked if e["fp"] > 0][:limit]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "grade": self.grade,
                "f1_score": round(self.f1_score, 4),
                "technique_recall": round(self.technique_recall, 4),
                "event_recall": round(self.event_recall, 4),
                "precision": round(self.precision, 4),
                "techniques_total": self.techniques_total,
                "techniques_detected": self.techniques_detected,
                "total_events": self.total_events,
                "total_malicious_events": self.total_malicious_events,
                "total_alerts": self.total_alerts,
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "alerts_per_true_positive": round(self.alert_volume_per_true_positive, 2),
            },
            "coverage": [c.to_dict() for c in self.coverage],
            "gaps": [c.to_dict() for c in self.gaps],
            "by_tactic": self.by_tactic(),
            "noisiest_rules": self.noisiest_rules(),
            "scenarios": [r.to_dict() for r in self.scenario_results],
        }


def score_scenario(
    scenario: Scenario,
    events: list[Event],
    alerts: list[Alert],
) -> list[CoverageScore]:
    """Compute per-technique coverage for a single scenario run."""
    scores: list[CoverageScore] = []

    for technique in scenario.techniques:
        tid = technique.technique_id
        generated = sum(1 for e in events if e.technique_id == tid)

        fired = 0
        genuine = 0
        rules: set[str] = set()

        for alert in alerts:
            if alert.event.technique_id != tid:
                continue
            fired += 1
            if alert.is_true_positive:
                genuine += 1
                rules.add(alert.rule_id)

        scores.append(
            CoverageScore(
                technique=technique,
                events_generated=generated,
                alerts_fired=fired,
                true_positives=genuine,
                detecting_rules=sorted(rules),
            )
        )

    return scores


def build_scorecard(
    runs: list[tuple[Scenario, ScenarioResult]],
) -> Scorecard:
    """Merge one or more scenario runs into a single scorecard.

    Techniques appearing in several scenarios are merged, so a technique detected
    in one chain but missed in another is reported as partial rather than clean.
    """
    merged: dict[str, CoverageScore] = {}
    results: list[ScenarioResult] = []

    total_events = 0
    total_malicious = 0
    total_alerts = 0
    tp = 0
    fp = 0

    for scenario, result in runs:
        results.append(result)
        total_events += len(result.events)
        total_malicious += len(result.malicious_events)
        total_alerts += len(result.alerts)
        tp += sum(1 for a in result.alerts if a.is_true_positive)
        fp += sum(1 for a in result.alerts if not a.is_true_positive)

        for score in score_scenario(scenario, result.events, result.alerts):
            tid = score.technique.technique_id
            existing = merged.get(tid)
            if existing is None:
                merged[tid] = score
                continue
            existing.events_generated += score.events_generated
            existing.alerts_fired += score.alerts_fired
            existing.true_positives += score.true_positives
            existing.detecting_rules = sorted(set(existing.detecting_rules) | set(score.detecting_rules))

    coverage = sorted(merged.values(), key=lambda c: (c.technique.tactic, c.technique.technique_id))

    return Scorecard(
        scenario_results=results,
        coverage=coverage,
        total_events=total_events,
        total_malicious_events=total_malicious,
        total_alerts=total_alerts,
        true_positives=tp,
        false_positives=fp,
    )
