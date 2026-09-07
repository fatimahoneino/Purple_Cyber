"""Statistical treatment of coverage metrics.

A single run reports a point estimate. Because benign noise, attacker
infrastructure and event ordering all vary with the seed, that number moves
between runs -- so quoting one run's precision to three decimals implies a
confidence the measurement does not support.

This module runs the assessment across many seeds and reports distributions with
confidence intervals. Two consequences matter:

* A change in the rule set can be called an improvement only when the intervals
  separate. Otherwise the difference is seed noise.
* Metric *stability* becomes visible. A rule set whose precision swings 30 points
  across seeds is fragile regardless of its mean, and that fragility is invisible
  in any single run.

Intervals are computed by bootstrap resampling rather than assuming a normal
distribution, since these metrics are bounded to [0,1] and visibly skewed near
the extremes, where a normal approximation produces intervals extending past 1.0.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass
from typing import Any, Callable, Sequence

_BOOTSTRAP_ITERATIONS = 2000


@dataclass
class MetricDistribution:
    """Distribution of one metric across repeated runs."""

    name: str
    samples: list[float]
    ci_low: float
    ci_high: float
    confidence: float

    @property
    def mean(self) -> float:
        return statistics.fmean(self.samples)

    @property
    def median(self) -> float:
        return statistics.median(self.samples)

    @property
    def stdev(self) -> float:
        # Population of one has no spread; stdev would raise.
        return statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0

    @property
    def spread(self) -> float:
        return max(self.samples) - min(self.samples)

    @property
    def coefficient_of_variation(self) -> float:
        """Relative volatility, comparable across metrics of different scale."""
        mean = self.mean
        return self.stdev / mean if mean else 0.0

    @property
    def stability(self) -> str:
        """Qualitative read on how much the metric moves between seeds."""
        cv = self.coefficient_of_variation
        if cv < 0.05:
            return "stable"
        if cv < 0.15:
            return "moderate"
        return "volatile"

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric": self.name,
            "runs": len(self.samples),
            "mean": round(self.mean, 4),
            "median": round(self.median, 4),
            "stdev": round(self.stdev, 4),
            "min": round(min(self.samples), 4),
            "max": round(max(self.samples), 4),
            "spread": round(self.spread, 4),
            "ci_low": round(self.ci_low, 4),
            "ci_high": round(self.ci_high, 4),
            "confidence": self.confidence,
            "coefficient_of_variation": round(self.coefficient_of_variation, 4),
            "stability": self.stability,
        }


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile. ``q`` in [0,1]."""
    if not values:
        raise ValueError("percentile of an empty sequence is undefined")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]

    position = q * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def bootstrap_ci(
    samples: Sequence[float],
    confidence: float = 0.95,
    iterations: int = _BOOTSTRAP_ITERATIONS,
    seed: int = 20260831,
) -> tuple[float, float]:
    """Percentile bootstrap confidence interval for the mean.

    Resamples with replacement and takes percentiles of the resampled means. Makes
    no distributional assumption, which matters because these metrics are bounded
    to [0,1]: a normal approximation would happily report an upper bound above 1.0
    for a rule set scoring near-perfect precision.

    The RNG is seeded so the interval is reproducible; an interval that shifts on
    every invocation is not something anyone can cite.
    """
    if not samples:
        raise ValueError("cannot bootstrap an empty sample")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be strictly between 0 and 1")
    if len(samples) == 1:
        return float(samples[0]), float(samples[0])

    rng = random.Random(seed)
    n = len(samples)
    means: list[float] = []

    for _ in range(iterations):
        resample = [samples[rng.randrange(n)] for _ in range(n)]
        means.append(statistics.fmean(resample))

    alpha = (1.0 - confidence) / 2.0
    return percentile(means, alpha), percentile(means, 1.0 - alpha)


def distribution(
    name: str,
    samples: Sequence[float],
    confidence: float = 0.95,
) -> MetricDistribution:
    low, high = bootstrap_ci(samples, confidence=confidence)
    return MetricDistribution(
        name=name,
        samples=list(samples),
        ci_low=low,
        ci_high=high,
        confidence=confidence,
    )


@dataclass
class StabilityReport:
    """Coverage metrics measured across many seeds."""

    seeds: list[int]
    metrics: dict[str, MetricDistribution]
    technique_detection_rates: dict[str, float]
    grades: list[str]

    @property
    def flaky_techniques(self) -> dict[str, float]:
        """Techniques detected in some runs but not others.

        These are the most actionable output of the whole report. A technique
        detected 60% of the time is not covered -- it is covered by accident,
        depending on where noise happened to fall. A single run reports it as a
        clean pass or a clean gap and hides the coin flip entirely.
        """
        return {
            technique: rate
            for technique, rate in sorted(self.technique_detection_rates.items())
            if 0.0 < rate < 1.0
        }

    @property
    def reliable_techniques(self) -> list[str]:
        return sorted(t for t, r in self.technique_detection_rates.items() if r == 1.0)

    @property
    def never_detected(self) -> list[str]:
        return sorted(t for t, r in self.technique_detection_rates.items() if r == 0.0)

    @property
    def modal_grade(self) -> str:
        return statistics.mode(self.grades)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runs": len(self.seeds),
            "seeds": self.seeds,
            "modal_grade": self.modal_grade,
            "grade_distribution": {g: self.grades.count(g) for g in sorted(set(self.grades))},
            "metrics": {name: dist.to_dict() for name, dist in self.metrics.items()},
            "technique_detection_rates": {
                k: round(v, 3) for k, v in sorted(self.technique_detection_rates.items())
            },
            "reliable_techniques": self.reliable_techniques,
            "flaky_techniques": {k: round(v, 3) for k, v in self.flaky_techniques.items()},
            "never_detected": self.never_detected,
        }


def compare(
    baseline: Sequence[float],
    candidate: Sequence[float],
    confidence: float = 0.95,
) -> dict[str, Any]:
    """Compare two metric samples and state whether the difference is real.

    Uses interval overlap on the difference of means. If the interval for the
    difference straddles zero, the change is indistinguishable from seed noise and
    is reported as such -- which is the guard against celebrating a rule change
    that did nothing.
    """
    if not baseline or not candidate:
        raise ValueError("both samples must be non-empty")

    base_mean = statistics.fmean(baseline)
    cand_mean = statistics.fmean(candidate)

    rng = random.Random(20260831)
    diffs: list[float] = []
    for _ in range(_BOOTSTRAP_ITERATIONS):
        b = statistics.fmean([baseline[rng.randrange(len(baseline))] for _ in baseline])
        c = statistics.fmean([candidate[rng.randrange(len(candidate))] for _ in candidate])
        diffs.append(c - b)

    alpha = (1.0 - confidence) / 2.0
    low = percentile(diffs, alpha)
    high = percentile(diffs, 1.0 - alpha)
    significant = low > 0 or high < 0

    return {
        "baseline_mean": round(base_mean, 4),
        "candidate_mean": round(cand_mean, 4),
        "difference": round(cand_mean - base_mean, 4),
        "ci_low": round(low, 4),
        "ci_high": round(high, 4),
        "confidence": confidence,
        "significant": significant,
        "interpretation": (
            f"{'improvement' if cand_mean > base_mean else 'regression'} is statistically "
            f"distinguishable from seed variance"
            if significant
            else "difference is within seed variance; not a demonstrable change"
        ),
    }


def run_stability_analysis(
    run_once: Callable[[int], dict[str, Any]],
    seeds: Sequence[int],
    confidence: float = 0.95,
) -> StabilityReport:
    """Execute the assessment across seeds and summarise the distributions.

    Args:
        run_once: Given a seed, returns a dict with ``technique_recall``,
            ``precision``, ``f1_score``, ``grade`` and ``detected_techniques``.
        seeds: Seeds to evaluate. Fewer than 5 produces intervals too wide to be
            useful; 20+ is preferable if runtime allows.
    """
    if not seeds:
        raise ValueError("at least one seed is required")

    collected: dict[str, list[float]] = {"technique_recall": [], "precision": [], "f1_score": []}
    grades: list[str] = []
    detection_counts: dict[str, int] = {}
    all_techniques: set[str] = set()

    for seed in seeds:
        outcome = run_once(seed)
        for metric in collected:
            collected[metric].append(float(outcome[metric]))
        grades.append(str(outcome["grade"]))

        detected = set(outcome["detected_techniques"])
        all_techniques.update(outcome["all_techniques"])
        for technique in detected:
            detection_counts[technique] = detection_counts.get(technique, 0) + 1

    rates = {t: detection_counts.get(t, 0) / len(seeds) for t in all_techniques}

    return StabilityReport(
        seeds=list(seeds),
        metrics={
            name: distribution(name, samples, confidence)
            for name, samples in collected.items()
        },
        technique_detection_rates=rates,
        grades=grades,
    )
