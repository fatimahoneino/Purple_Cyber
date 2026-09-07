"""Streaming, per-entity behavioural anomaly baselines.

Events are scored before they update their baseline.  This avoids hiding the
current observation in its own statistics, while median/MAD and Welford's
algorithm keep scoring resistant to outliers and floating-point cancellation.
"""

from __future__ import annotations

import math
import statistics
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping

from purpleforge.models import Event

_EPSILON = 1e-12
_MAD_SCALE = 1.4826


@dataclass
class RunningStats:
    """Numerically stable online sample statistics (Welford's algorithm)."""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        if not math.isfinite(value):
            return
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def variance(self) -> float:
        return self.m2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def standard_deviation(self) -> float:
        return math.sqrt(max(0.0, self.variance))


@dataclass
class FeatureBaseline:
    """Streaming moments plus a bounded robust-reference sample."""

    robust_window: int = 101
    stats: RunningStats = field(default_factory=RunningStats)
    _recent: deque[float] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.robust_window < 3:
            raise ValueError("robust_window must be at least 3")
        self._recent = deque(maxlen=self.robust_window)

    def update(self, value: float) -> None:
        if math.isfinite(value):
            self.stats.update(value)
            self._recent.append(value)

    @property
    def count(self) -> int:
        return self.stats.count

    @property
    def median(self) -> float:
        return statistics.median(self._recent) if self._recent else 0.0

    @property
    def mad(self) -> float:
        if not self._recent:
            return 0.0
        center = self.median
        return statistics.median(abs(value - center) for value in self._recent)

    def score(self, value: float, min_samples: int) -> tuple[float, str, float, float]:
        """Return score, method, centre, and scale; never divide by zero."""
        if self.count < min_samples:
            return 0.0, "insufficient_samples", self.median, 0.0
        median, mad = self.median, self.mad
        robust_scale = _MAD_SCALE * mad
        if robust_scale > _EPSILON:
            return abs(value - median) / robust_scale, "median_mad", median, robust_scale
        deviation = abs(value - self.stats.mean)
        stddev = self.stats.standard_deviation
        if stddev > _EPSILON:
            return deviation / stddev, "welford_zscore", self.stats.mean, stddev
        # A constant baseline has no measurable variance. Equal values are normal;
        # changed values receive an explicit infinite score, not a divide-by-zero.
        score = 0.0 if deviation <= _EPSILON else math.inf
        return score, "zero_variance", self.stats.mean, 0.0


@dataclass(frozen=True)
class AnomalyFinding:
    event_id: str
    timestamp: datetime
    entity: str
    feature: str
    value: float
    score: float
    threshold: float
    sample_count: int
    method: str
    explanation: str

    @property
    def is_anomaly(self) -> bool:
        return self.score >= self.threshold

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "entity": self.entity,
            "feature": self.feature,
            "value": self.value,
            "score": self.score,
            "threshold": self.threshold,
            "sample_count": self.sample_count,
            "method": self.method,
            "explanation": self.explanation,
        }


def extract_features(event: Event) -> dict[str, float]:
    """Extract stable numeric and behavioural features from a PurpleForge Event."""
    features: dict[str, float] = {
        "time.hour": float(event.timestamp.hour + event.timestamp.minute / 60.0),
        "event.field_count": float(len(event.fields)),
    }
    for key, value in sorted(event.fields.items()):
        if isinstance(value, bool):
            features[key] = float(value)
        elif isinstance(value, (int, float)) and math.isfinite(float(value)):
            features[key] = float(value)
    for key in ("process.command_line", "process.name", "destination.domain"):
        value = event.fields.get(key)
        if isinstance(value, str):
            features[f"{key}.length"] = float(len(value))
    return features


class BehavioralBaseline:
    """Maintain and score independent feature baselines for each entity.

    By default the entity combines host and user, avoiding cross-user pollution
    on shared hosts. Callers may provide a different deterministic entity key.
    """

    def __init__(
        self,
        min_samples: int = 5,
        threshold: float = 3.5,
        robust_window: int = 101,
        entity_key: Callable[[Event], str] | None = None,
    ) -> None:
        if min_samples < 2:
            raise ValueError("min_samples must be at least 2")
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        if robust_window < min_samples:
            raise ValueError("robust_window cannot be smaller than min_samples")
        self.min_samples = min_samples
        self.threshold = float(threshold)
        self.robust_window = robust_window
        self.entity_key = entity_key or (lambda event: f"host:{event.host}|user:{event.user}")
        self._baselines: dict[str, dict[str, FeatureBaseline]] = {}
        self._entity_counts: dict[str, int] = {}

    def score_event(self, event: Event, *, learn: bool = False) -> list[AnomalyFinding]:
        """Score an event against prior observations.

        ``learn`` defaults to false. Production detectors should not let the event
        currently under judgment rewrite its own baseline; that is how slow attacks
        poison a behavioral model until abnormal becomes normal. Call :meth:`fit`
        on an explicit historical calibration period, then score live events without
        learning. ``observe`` remains available for controlled streaming use.
        """
        entity = str(self.entity_key(event))
        features = extract_features(event)
        entity_baselines = self._baselines.setdefault(entity, {})
        entity_mature = self._entity_counts.get(entity, 0) >= self.min_samples
        findings: list[AnomalyFinding] = []
        for feature, value in sorted(features.items()):
            is_new_feature = feature not in entity_baselines
            baseline = entity_baselines.setdefault(
                feature, FeatureBaseline(robust_window=self.robust_window)
            )
            if is_new_feature and entity_mature:
                findings.append(
                    AnomalyFinding(
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        entity=entity,
                        feature=feature,
                        value=value,
                        score=math.inf,
                        threshold=self.threshold,
                        sample_count=self._entity_counts.get(entity, 0),
                        method="feature_novelty",
                        explanation=(
                            f"{feature} appeared for the first time after "
                            f"{self._entity_counts.get(entity, 0)} baseline events"
                        ),
                    )
                )
            else:
                score, method, center, scale = baseline.score(value, self.min_samples)
                if score >= self.threshold:
                    rendered = "infinite" if math.isinf(score) else f"{score:.2f}"
                    if method == "zero_variance":
                        detail = f"changed from constant baseline {center:g}"
                    else:
                        detail = f"is {rendered} robust deviations from {center:g} (scale {scale:g})"
                    findings.append(
                        AnomalyFinding(
                            event_id=event.event_id,
                            timestamp=event.timestamp,
                            entity=entity,
                            feature=feature,
                            value=value,
                            score=score,
                            threshold=self.threshold,
                            sample_count=baseline.count,
                            method=method,
                            explanation=f"{feature}={value:g} {detail} across {baseline.count} prior samples",
                        )
                    )
            if learn:
                baseline.update(value)
        if learn:
            self._entity_counts[entity] = self._entity_counts.get(entity, 0) + 1
        return findings

    def fit(self, events: Iterable[Event]) -> int:
        """Learn from an explicit calibration set without producing alerts."""
        learned = 0
        for event in events:
            entity = str(self.entity_key(event))
            for feature, value in extract_features(event).items():
                baseline = self._baselines.setdefault(entity, {}).setdefault(
                    feature, FeatureBaseline(robust_window=self.robust_window)
                )
                baseline.update(value)
            self._entity_counts[entity] = self._entity_counts.get(entity, 0) + 1
            learned += 1
        return learned

    def observe(self, event: Event) -> list[AnomalyFinding]:
        """Score then learn, for controlled streaming environments."""
        return self.score_event(event, learn=True)

    def process(self, events: Iterable[Event], *, learn: bool = True) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []
        for event in events:
            findings.extend(self.score_event(event, learn=learn))
        return findings

    def snapshot(self) -> Mapping[str, Mapping[str, FeatureBaseline]]:
        """Expose current baseline state as read-only-by-convention mappings."""
        return {entity: dict(features) for entity, features in self._baselines.items()}


# Descriptive alias for callers that prefer an engine-style API.
BaselineEngine = BehavioralBaseline
