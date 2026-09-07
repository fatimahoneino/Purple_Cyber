"""Stateful correlation rules.

Single-event rules cannot express the behaviours that matter most in real intrusion
detection, because the individually-benign-but-collectively-malicious pattern is
precisely how competent operators stay under the threshold. Three shapes cover the
bulk of production correlation logic:

``sequence``
    Ordered stages within a window on a shared key. Detects kill-chain progression:
    recon, then credential access, then lateral movement on one host. No single
    stage needs to be alarming.

``threshold``
    N matches of one condition within a window. Detects brute force and spray
    activity, where the volume is the signal and any one event is unremarkable.

``distinct``
    N *unique* values of a field within a window. Distinguishes one source hitting
    many destinations (scanning) from one source retrying the same destination
    (a misconfigured client). A plain threshold conflates the two.

All three use a sliding window over time-ordered events. Windowing is deliberately
strict: an unbounded correlation would eventually match any event set given enough
telemetry, which yields impressive-looking recall and no real detection value.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from purpleforge.detection.engine import RuleSyntaxError, _match_selection
from purpleforge.models import Alert, Event, Severity, TechniqueRef, utcnow

_VALID_TYPES = {"sequence", "threshold", "distinct"}


@dataclass
class CorrelationStage:
    """One named stage of a sequence rule.

    ``exclude`` is an optional selection that vetoes a match. Without it, tuning
    out a known-benign source means loosening the main selection, which usually
    gives up the detection it was written for.
    """

    name: str
    selection: dict[str, Any]
    exclude: dict[str, Any] | None = None

    def matches(self, event: Event) -> bool:
        flat = event.flatten()
        if not _match_selection(self.selection, flat):
            return False
        if self.exclude and _match_selection(self.exclude, flat):
            return False
        return True


@dataclass
class CorrelationRule:
    """A stateful analytic spanning multiple events.

    Args:
        window_seconds: Sliding window width. Required and bounded, because an
            unbounded window makes the rule meaningless.
        group_by: Field that must be equal across correlated events, usually
            ``host`` or ``user``. Without it, unrelated activity on different
            machines would correlate into phantom intrusions.
        stages: Ordered stages, for ``sequence`` rules.
        selection: Single condition, for ``threshold`` and ``distinct`` rules.
        threshold: Match count required to fire.
        distinct_field: Field whose unique values are counted, for ``distinct``.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    correlation_type: str
    window_seconds: int
    techniques: list[TechniqueRef] = field(default_factory=list)
    group_by: str = "host"
    stages: list[CorrelationStage] = field(default_factory=list)
    selection: dict[str, Any] | None = None
    threshold: int = 1
    distinct_field: str | None = None
    source: str = "handwritten"
    false_positives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.correlation_type not in _VALID_TYPES:
            raise RuleSyntaxError(
                f"{self.rule_id}: correlation type must be one of {sorted(_VALID_TYPES)}, "
                f"got {self.correlation_type!r}"
            )
        if self.window_seconds <= 0:
            raise RuleSyntaxError(
                f"{self.rule_id}: window_seconds must be positive; an unbounded "
                "window eventually matches anything"
            )
        if self.correlation_type == "sequence":
            if len(self.stages) < 2:
                raise RuleSyntaxError(
                    f"{self.rule_id}: a sequence needs at least 2 stages, "
                    "otherwise it is a single-event rule"
                )
        else:
            if not self.selection:
                raise RuleSyntaxError(
                    f"{self.rule_id}: {self.correlation_type} rules require a selection"
                )
            if self.threshold < 2:
                raise RuleSyntaxError(
                    f"{self.rule_id}: threshold must be at least 2, "
                    "otherwise it is a single-event rule"
                )
        if self.correlation_type == "distinct" and not self.distinct_field:
            raise RuleSyntaxError(f"{self.rule_id}: distinct rules require distinct_field")

    @property
    def technique_ids(self) -> set[str]:
        return {t.technique_id for t in self.techniques}

    @property
    def window(self) -> timedelta:
        return timedelta(seconds=self.window_seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "correlation_type": self.correlation_type,
            "window_seconds": self.window_seconds,
            "group_by": self.group_by,
            "threshold": self.threshold,
            "distinct_field": self.distinct_field,
            "stages": [s.name for s in self.stages],
            "techniques": [
                {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic}
                for t in self.techniques
            ],
            "source": self.source,
            "false_positives": self.false_positives,
            "references": self.references,
            "enabled": self.enabled,
        }


class CorrelationEngine:
    """Evaluates correlation rules over a time-ordered event stream.

    Each rule fires at most once per group key per window. Without that cap a
    sequence rule would emit an alert for every subsequent matching event in the
    window, burying the analyst in duplicates of one finding -- the same
    alert-fatigue problem correlation is meant to solve.
    """

    def __init__(self, rules: list[CorrelationRule]) -> None:
        self.rules = rules
        self.errors: list[dict[str, str]] = []

    @property
    def enabled_rules(self) -> list[CorrelationRule]:
        return [r for r in self.rules if r.enabled]

    @staticmethod
    def _group_key(event: Event, field_name: str) -> str | None:
        value = event.flatten().get(field_name)
        return None if value is None else str(value)

    def _group(self, events: list[Event], field_name: str) -> dict[str, list[Event]]:
        groups: dict[str, list[Event]] = {}
        for event in events:
            key = self._group_key(event, field_name)
            if key is not None:
                groups.setdefault(key, []).append(event)
        for bucket in groups.values():
            bucket.sort(key=lambda e: e.timestamp)
        return groups

    # ---------------------------------------------------------------- sequence

    def _eval_sequence(self, rule: CorrelationRule, events: list[Event]) -> list[list[Event]]:
        """Find ordered stage completions within the window.

        Greedy forward scan: for each candidate start, advance through the stages
        taking the earliest event that satisfies the next one. Earliest-match keeps
        the window as tight as possible, so a completion reported here is the
        strongest available evidence rather than the most convenient.
        """
        hits: list[list[Event]] = []
        consumed: set[str] = set()

        for index, first in enumerate(events):
            if first.event_id in consumed or not rule.stages[0].matches(first):
                continue

            chain = [first]
            stage_index = 1
            deadline = first.timestamp + rule.window

            for candidate in events[index + 1 :]:
                if candidate.timestamp > deadline:
                    break
                if candidate.event_id in consumed:
                    continue
                if rule.stages[stage_index].matches(candidate):
                    chain.append(candidate)
                    stage_index += 1
                    if stage_index == len(rule.stages):
                        break

            if stage_index == len(rule.stages):
                hits.append(chain)
                consumed.update(e.event_id for e in chain)

        return hits

    # --------------------------------------------------- threshold / distinct

    def _eval_threshold(self, rule: CorrelationRule, events: list[Event]) -> list[list[Event]]:
        matching = [e for e in events if _match_selection(rule.selection, e.flatten())]
        hits: list[list[Event]] = []
        start = 0

        for end in range(len(matching)):
            # Shrink from the left until the window holds.
            while matching[end].timestamp - matching[start].timestamp > rule.window:
                start += 1

            bucket = matching[start : end + 1]

            if rule.correlation_type == "distinct":
                values = {
                    str(e.flatten().get(rule.distinct_field))
                    for e in bucket
                    if e.flatten().get(rule.distinct_field) is not None
                }
                fired = len(values) >= rule.threshold
            else:
                fired = len(bucket) >= rule.threshold

            if fired:
                hits.append(bucket)
                start = end + 1  # one alert per window, not one per event

        return hits

    # ------------------------------------------------------------------ public

    def run(self, events: list[Event]) -> list[Alert]:
        """Evaluate every enabled correlation rule. Broken rules are isolated."""
        alerts: list[Alert] = []
        ordered = sorted(events, key=lambda e: e.timestamp)

        for rule in self.enabled_rules:
            try:
                for key, bucket in self._group(ordered, rule.group_by).items():
                    if rule.correlation_type == "sequence":
                        hits = self._eval_sequence(rule, bucket)
                    else:
                        hits = self._eval_threshold(rule, bucket)

                    for chain in hits:
                        # The last event completes the pattern, so it is the point
                        # at which a real SIEM would raise the alert.
                        trigger = chain[-1]
                        alerts.append(
                            Alert(
                                alert_id=uuid.uuid4().hex[:12],
                                rule_id=rule.rule_id,
                                rule_title=rule.title,
                                severity=rule.severity,
                                event=trigger,
                                matched_at=utcnow(),
                                techniques=sorted(rule.technique_ids),
                                supporting_events=[e for e in chain if e.event_id != trigger.event_id],
                                correlation_type=f"{rule.correlation_type}:{rule.group_by}={key}",
                            )
                        )
            except RuleSyntaxError as exc:
                self.errors.append({"rule_id": rule.rule_id, "error": str(exc)})

        alerts.sort(key=lambda a: (a.event.timestamp, -a.severity.rank))
        return alerts

    def validate(self) -> list[dict[str, str]]:
        """Syntax-check every rule's selections against a probe event."""
        probe = Event(
            timestamp=utcnow(),
            source="probe",
            event_type="probe",
            host="probe",
            user="probe",
            fields={},
        )
        problems: list[dict[str, str]] = []

        for rule in self.rules:
            try:
                for stage in rule.stages:
                    stage.matches(probe)
                if rule.selection:
                    _match_selection(rule.selection, probe.flatten())
            except RuleSyntaxError as exc:
                problems.append({"rule_id": rule.rule_id, "error": str(exc)})

        return problems
