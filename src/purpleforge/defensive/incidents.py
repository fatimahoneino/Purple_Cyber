"""Deterministic alert-to-incident reconstruction.

Alerts are joined only when they share a host, user, or destination and occur
within the configured window. Ground truth is isolated to evaluation metrics;
it never participates in graph construction, risk, ordering, or identifiers.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Iterable, Mapping

from purpleforge.models import Alert, Event

_TACTIC_ORDER = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
)
_TACTIC_RANK = {name: index for index, name in enumerate(_TACTIC_ORDER)}
_DEFAULT_TECHNIQUE_TACTICS = {
    "T1003": "credential-access", "T1003.001": "credential-access",
    "T1021": "lateral-movement", "T1021.002": "lateral-movement",
    "T1041": "exfiltration", "T1046": "discovery", "T1052": "exfiltration",
    "T1052.001": "exfiltration", "T1059": "execution", "T1059.001": "execution",
    "T1087": "discovery", "T1087.002": "discovery", "T1133": "initial-access",
    "T1134": "privilege-escalation", "T1134.001": "privilege-escalation",
    "T1213": "collection", "T1213.003": "collection", "T1486": "impact",
    "T1490": "impact", "T1546": "persistence", "T1546.003": "persistence",
    "T1560": "collection", "T1560.001": "collection", "T1562": "defense-evasion",
    "T1562.001": "defense-evasion", "T1566": "initial-access",
    "T1566.001": "initial-access", "T1567": "exfiltration",
    "T1567.002": "exfiltration",
}
_SEVERITY_RISK = {"info": 10.0, "low": 25.0, "medium": 50.0, "high": 75.0, "critical": 95.0}


@dataclass(frozen=True)
class TacticStage:
    tactic: str
    first_seen: Any
    techniques: tuple[str, ...]
    alert_ids: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceLineage:
    alert_id: str
    rule_id: str
    event_ids: tuple[str, ...]
    entities: tuple[str, ...]


@dataclass
class Incident:
    incident_id: str
    alerts: list[Alert]
    started_at: Any
    ended_at: Any
    risk_score: float
    confidence: float
    entities: tuple[str, ...]
    tactic_progression: tuple[TacticStage, ...]
    evidence_lineage: tuple[EvidenceLineage, ...]

    @property
    def alert_ids(self) -> tuple[str, ...]:
        return tuple(alert.alert_id for alert in self.alerts)

    @property
    def purity(self) -> float:
        """Ground-truth evaluation metric; deliberately excluded from ranking."""
        return (
            sum(1 for alert in self.alerts if alert.is_true_positive) / len(self.alerts)
            if self.alerts else 0.0
        )

    @property
    def event_purity(self) -> float:
        events = {event.event_id: event for alert in self.alerts for event in alert.all_events}
        return sum(event.is_malicious for event in events.values()) / len(events) if events else 0.0

    def evaluation(self) -> dict[str, float]:
        return {"alert_purity": self.purity, "event_purity": self.event_purity}


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1


def _event_entities(event: Event) -> set[str]:
    entities = set()
    if event.host:
        entities.add(f"host:{event.host.casefold()}")
    if event.user:
        entities.add(f"user:{event.user.casefold()}")
    for key in ("destination.ip", "destination.domain"):
        value = event.fields.get(key)
        if value not in (None, ""):
            entities.add(f"destination:{str(value).casefold()}")
    return entities


def _alert_entities(alert: Alert) -> set[str]:
    return set().union(*(_event_entities(event) for event in alert.all_events))


def _alert_time(alert: Alert) -> Any:
    """Telemetry time at which the evidence occurred.

    ``matched_at`` is batch-processing time. In an offline replay every alert is
    matched within milliseconds, so using it would collapse activity hours apart
    into one incident. The triggering event timestamp preserves the timeline the
    defender actually needs to reconstruct.
    """
    return alert.event.timestamp


def _canonical_key(alert: Alert) -> tuple[Any, ...]:
    """Collapse repeat firings for the same rule and evidence.

    Technique metadata is intentionally excluded: enrichment differences do not
    make two firings over identical evidence independent risk signals.
    """
    return alert.rule_id, tuple(sorted(event.event_id for event in alert.all_events))


def _alert_risk(alert: Alert) -> float:
    triage = (alert.triage or {}).get("risk_score")
    if isinstance(triage, (int, float)) and math.isfinite(float(triage)):
        return min(100.0, max(0.0, float(triage)))
    return _SEVERITY_RISK.get(alert.severity.value, 0.0)


def _aggregate_risk(alerts: Iterable[Alert]) -> float:
    unique: dict[tuple[Any, ...], Alert] = {}
    for alert in alerts:
        key = _canonical_key(alert)
        incumbent = unique.get(key)
        if incumbent is None or _alert_risk(alert) > _alert_risk(incumbent):
            unique[key] = alert
    # Independent-evidence union: bounded at 100 and unaffected by duplicates.
    residual = 1.0
    for alert in unique.values():
        residual *= 1.0 - _alert_risk(alert) / 100.0
    return round(100.0 * (1.0 - residual), 2)


def _tactic_for(technique: str, mapping: Mapping[str, str]) -> str | None:
    return mapping.get(technique) or mapping.get(technique.split(".", 1)[0])


def _progression(alerts: list[Alert], mapping: Mapping[str, str]) -> tuple[TacticStage, ...]:
    stages: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        for technique in sorted(set(alert.techniques)):
            tactic = _tactic_for(technique, mapping)
            if not tactic:
                continue
            stage = stages.setdefault(
                tactic, {"first_seen": _alert_time(alert), "techniques": set(), "alerts": set()}
            )
            stage["first_seen"] = min(stage["first_seen"], _alert_time(alert))
            stage["techniques"].add(technique)
            stage["alerts"].add(alert.alert_id)
    ordered = sorted(stages, key=lambda tactic: (_TACTIC_RANK.get(tactic, len(_TACTIC_ORDER)), tactic))
    return tuple(
        TacticStage(
            tactic=tactic,
            first_seen=stages[tactic]["first_seen"],
            techniques=tuple(sorted(stages[tactic]["techniques"])),
            alert_ids=tuple(sorted(stages[tactic]["alerts"])),
        )
        for tactic in ordered
    )


def _confidence(alerts: list[Alert], entities: set[str], progression: tuple[TacticStage, ...]) -> float:
    """Operational confidence from observable corroboration, never ground truth."""
    unique_evidence = {event.event_id for alert in alerts for event in alert.all_events}
    unique_rules = {alert.rule_id for alert in alerts}
    duplicate_ratio = len({_canonical_key(alert) for alert in alerts}) / len(alerts)
    corroboration = min(1.0, (len(unique_rules) - 1) / 3.0)
    breadth = min(1.0, (len(entities) - 1) / 4.0)
    evidence = min(1.0, len(unique_evidence) / 5.0)
    tactics = min(1.0, len(progression) / 4.0)
    confidence = 0.15 + 0.25 * corroboration + 0.2 * breadth + 0.2 * evidence + 0.2 * tactics
    return round(confidence * duplicate_ratio, 3)


class IncidentReconstructor:
    def __init__(self, window: timedelta = timedelta(minutes=15), technique_tactics: Mapping[str, str] | None = None) -> None:
        if window.total_seconds() < 0:
            raise ValueError("window cannot be negative")
        self.window = window
        self.technique_tactics = dict(_DEFAULT_TECHNIQUE_TACTICS)
        if technique_tactics:
            self.technique_tactics.update(technique_tactics)

    def reconstruct(self, alerts: Iterable[Alert]) -> list[Incident]:
        ordered = sorted(alerts, key=lambda alert: (_alert_time(alert), alert.alert_id, alert.rule_id))
        if not ordered:
            return []
        union = _UnionFind(len(ordered))
        recent: dict[str, deque[tuple[Any, int]]] = defaultdict(deque)
        entities_by_index: list[set[str]] = []
        for index, alert in enumerate(ordered):
            event_time = _alert_time(alert)
            entities = _alert_entities(alert)
            entities_by_index.append(entities)
            for entity in sorted(entities):
                candidates = recent[entity]
                cutoff = event_time - self.window
                while candidates and candidates[0][0] < cutoff:
                    candidates.popleft()
                for _, previous in candidates:
                    union.union(index, previous)
                candidates.append((event_time, index))

        components: dict[int, list[int]] = defaultdict(list)
        for index in range(len(ordered)):
            components[union.find(index)].append(index)
        incidents = [self._build(ordered, entities_by_index, indices) for indices in components.values()]
        # Ground truth is intentionally absent from this ranking key.
        return sorted(incidents, key=lambda item: (-item.risk_score, -item.confidence, item.started_at, item.incident_id))

    def _build(self, alerts: list[Alert], entities_by_index: list[set[str]], indices: list[int]) -> Incident:
        members = [alerts[index] for index in sorted(indices)]
        entities = set().union(*(entities_by_index[index] for index in indices))
        progression = _progression(members, self.technique_tactics)
        digest = hashlib.sha256("\0".join(sorted(alert.alert_id for alert in members)).encode()).hexdigest()[:16]
        lineage = tuple(
            EvidenceLineage(
                alert_id=alert.alert_id,
                rule_id=alert.rule_id,
                event_ids=tuple(sorted(event.event_id for event in alert.all_events)),
                entities=tuple(sorted(_alert_entities(alert))),
            )
            for alert in members
        )
        return Incident(
            incident_id=f"inc-{digest}",
            alerts=members,
            started_at=min(_alert_time(alert) for alert in members),
            ended_at=max(_alert_time(alert) for alert in members),
            risk_score=_aggregate_risk(members),
            confidence=_confidence(members, entities, progression),
            entities=tuple(sorted(entities)),
            tactic_progression=progression,
            evidence_lineage=lineage,
        )


def reconstruct_incidents(
    alerts: Iterable[Alert],
    window: timedelta = timedelta(minutes=15),
    technique_tactics: Mapping[str, str] | None = None,
) -> list[Incident]:
    return IncidentReconstructor(window, technique_tactics).reconstruct(alerts)
