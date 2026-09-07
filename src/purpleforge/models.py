"""Core domain models shared by the red, blue and purple layers.

Everything is a plain dataclass so the whole pipeline stays serialisable to JSON
without pulling a database into the picture. Telemetry is normalised into a
single flat :class:`Event` shape modelled loosely on the Elastic Common Schema,
which is what lets one detection rule match events from several sources.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered severity scale. Values match common SIEM conventions."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]

    # All four comparisons are defined explicitly. Severity subclasses str, so
    # without these Python falls back to alphabetical comparison and
    # "critical" > "high" evaluates False, silently mis-ordering every queue.
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class TechniqueRef:
    """A reference to a MITRE ATT&CK technique or sub-technique."""

    technique_id: str
    name: str
    tactic: str

    def __post_init__(self) -> None:
        if not self.technique_id.startswith("T"):
            raise ValueError(f"ATT&CK technique ids start with 'T', got {self.technique_id!r}")

    @property
    def base_technique(self) -> str:
        """``T1059.001`` -> ``T1059``. Used to roll sub-techniques up in reports."""
        return self.technique_id.split(".", 1)[0]

    @property
    def url(self) -> str:
        path = self.technique_id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{path}/"


@dataclass
class Event:
    """One normalised telemetry record.

    ``labels`` carries red-team ground truth. A synthetic event emitted by a
    scenario step is tagged with the technique that produced it, which is what
    makes automated true/false positive scoring possible. Benign noise events
    carry no technique label.
    """

    timestamp: datetime
    source: str
    event_type: str
    host: str
    user: str
    fields: dict[str, Any] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    event_id: str = ""

    def __post_init__(self) -> None:
        # Derived from content rather than random, so two runs from the same seed
        # produce identical ids. A random id here would silently break the
        # reproducibility guarantee the whole scoring model relies on.
        if not self.event_id:
            blob = json.dumps(
                {
                    "t": self.timestamp.isoformat(),
                    "s": self.source,
                    "e": self.event_type,
                    "h": self.host,
                    "u": self.user,
                    "f": self.fields,
                    "l": self.labels,
                },
                sort_keys=True,
                default=str,
            )
            object.__setattr__(
                self, "event_id", hashlib.sha256(blob.encode()).hexdigest()[:16]
            )

    @property
    def is_malicious(self) -> bool:
        """True when red-side ground truth marks this event as attack activity."""
        return "technique_id" in self.labels

    @property
    def technique_id(self) -> str | None:
        return self.labels.get("technique_id")

    def flatten(self) -> dict[str, Any]:
        """Flatten to a single namespace so rules can select on any attribute.

        Nested ``fields`` are hoisted to the top level and also kept under a
        dotted path, so a rule may match either ``process.command_line`` or the
        bare ``command_line``.
        """
        flat: dict[str, Any] = {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "host": self.host,
            "user": self.user,
        }
        for key, value in self.fields.items():
            flat[key] = value
            if "." in key:
                flat[key.rsplit(".", 1)[-1]] = value
        return flat

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Event:
        data = dict(payload)
        ts = data.pop("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return cls(timestamp=ts, **data)


@dataclass
class DetectionRule:
    """A Sigma-flavoured analytic.

    The condition grammar is deliberately small -- ``and``/``or``/``not`` over
    named selections -- because a compact, fully understood matcher is more
    useful here than partial support for the entire Sigma spec.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    techniques: list[TechniqueRef]
    detection: dict[str, Any]
    condition: str
    source: str = "handwritten"
    false_positives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    enabled: bool = True

    @property
    def technique_ids(self) -> set[str]:
        return {t.technique_id for t in self.techniques}

    @property
    def fingerprint(self) -> str:
        """Stable hash of matching logic, used to spot duplicate AI proposals."""
        blob = json.dumps(
            {"detection": self.detection, "condition": self.condition},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "techniques": [asdict(t) for t in self.techniques],
            "detection": self.detection,
            "condition": self.condition,
            "source": self.source,
            "false_positives": self.false_positives,
            "references": self.references,
            "enabled": self.enabled,
        }


@dataclass
class Alert:
    """A rule firing, plus the AI triage verdict once enriched.

    ``event`` is the triggering event. ``supporting_events`` is populated only by
    correlation rules, which fire on a *set* of events rather than one, so an
    analyst can see the whole chain that caused the alert.
    """

    alert_id: str
    rule_id: str
    rule_title: str
    severity: Severity
    event: Event
    matched_at: datetime
    techniques: list[str] = field(default_factory=list)
    triage: dict[str, Any] | None = None
    supporting_events: list[Event] = field(default_factory=list)
    correlation_type: str | None = None

    @property
    def is_correlation(self) -> bool:
        return bool(self.supporting_events)

    @property
    def all_events(self) -> list[Event]:
        """Triggering event plus any supporting events, de-duplicated by id."""
        seen: dict[str, Event] = {self.event.event_id: self.event}
        for event in self.supporting_events:
            seen.setdefault(event.event_id, event)
        return list(seen.values())

    def _claims(self, event: Event) -> bool:
        """Whether this rule's ATT&CK tags cover the technique that produced ``event``.

        An untagged rule is credited for any malicious event; a tagged rule is only
        credited when its claim matches, so catching the right event for the wrong
        reason earns nothing. Sub-techniques roll up, so a rule tagged ``T1059``
        gets credit for ``T1059.001``.
        """
        if not event.is_malicious:
            return False
        if not self.techniques:
            return True
        actual = event.technique_id or ""
        base = actual.split(".", 1)[0]
        return any(t == actual or t == base or t.startswith(base) for t in self.techniques)

    @property
    def is_true_positive(self) -> bool:
        """Graded against red-side ground truth, not against the triage verdict.

        For a correlation alert the criterion generalises to the event set: the
        firing is genuine when at least one correlated event was attack activity
        whose technique the rule claims. A correlation assembled entirely from
        benign events is a false positive no matter how many events it spans.
        """
        if not self.is_correlation:
            return self._claims(self.event)
        return any(self._claims(event) for event in self.all_events)

    @property
    def correlation_purity(self) -> float:
        """Fraction of correlated events that were genuine attack activity.

        Exposed because a correlation can be technically a true positive while
        being mostly noise. Low purity means the analyst has to sift the chain
        themselves, which is the failure mode correlation is supposed to prevent.
        """
        events = self.all_events
        if not events:
            return 0.0
        return sum(1 for e in events if e.is_malicious) / len(events)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity.value,
            "event": self.event.to_dict(),
            "matched_at": self.matched_at.isoformat(),
            "techniques": self.techniques,
            "triage": self.triage,
            "verdict": "true_positive" if self.is_true_positive else "false_positive",
        }
        if self.is_correlation:
            payload["correlation"] = {
                "type": self.correlation_type,
                "event_count": len(self.all_events),
                "purity": round(self.correlation_purity, 3),
                "supporting_events": [e.to_dict() for e in self.supporting_events],
            }
        return payload


@dataclass
class ScenarioResult:
    """Outcome of one emulation run: what red did, and what blue saw."""

    scenario_id: str
    scenario_name: str
    started_at: datetime
    finished_at: datetime
    events: list[Event]
    alerts: list[Alert]
    techniques_executed: list[TechniqueRef]

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def malicious_events(self) -> list[Event]:
        return [e for e in self.events if e.is_malicious]

    @property
    def detected_techniques(self) -> set[str]:
        """Techniques with at least one genuine detection."""
        return {
            a.event.technique_id
            for a in self.alerts
            if a.is_true_positive and a.event.technique_id
        }

    @property
    def missed_techniques(self) -> set[str]:
        return {t.technique_id for t in self.techniques_executed} - self.detected_techniques

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "event_count": len(self.events),
            "malicious_event_count": len(self.malicious_events),
            "alert_count": len(self.alerts),
            "techniques_executed": [asdict(t) for t in self.techniques_executed],
            "detected_techniques": sorted(self.detected_techniques),
            "missed_techniques": sorted(self.missed_techniques),
            "alerts": [a.to_dict() for a in self.alerts],
        }


def utcnow() -> datetime:
    """Timezone-aware UTC now. Naive datetimes cause silent ordering bugs."""
    return datetime.now(timezone.utc)
