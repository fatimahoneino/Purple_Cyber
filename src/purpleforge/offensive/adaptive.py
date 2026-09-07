"""Detection-aware adaptation for safe, metadata-only attack plans.

Adaptive planning records simulated defensive feedback and asks the graph planner
for a less exposed route.  Timing dilation is represented solely as annotations
for evaluating correlation-window assumptions; this module contains no sleeping,
scheduling, process execution, or network behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Iterable

from purpleforge.offensive.environment import Environment
from purpleforge.offensive.planner import AttackPlan, AttackPlanner


@dataclass(frozen=True)
class DetectionFeedback:
    """A simulated detection observation used to discourage repeated exposure."""

    technique_id: str | None = None
    host: str | None = None
    confidence: float = 1.0
    severity: float = 1.0
    note: str = ""

    def __post_init__(self) -> None:
        if self.technique_id is None and self.host is None:
            raise ValueError("feedback must identify a technique, host, or both")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.severity < 0:
            raise ValueError("severity must be non-negative")

    @property
    def penalty(self) -> float:
        """Return the confidence-adjusted additive planning penalty."""
        return self.confidence * self.severity


@dataclass(frozen=True)
class TimingDilation:
    """Metadata describing a hypothetical correlation-window timing change.

    This record deliberately does not implement delays.  It allows defenders to
    label plans with assumptions such as an event interval exceeding a SIEM
    correlation window and then assess whether detections remain robust.
    """

    correlation_window_seconds: float
    simulated_interval_seconds: float
    rationale: str = "Defensive correlation-window resilience simulation."

    def __post_init__(self) -> None:
        if self.correlation_window_seconds <= 0:
            raise ValueError("correlation window must be positive")
        if self.simulated_interval_seconds < 0:
            raise ValueError("simulated interval must be non-negative")

    @property
    def exceeds_window(self) -> bool:
        """Whether the modelled interval is outside the correlation window."""
        return self.simulated_interval_seconds > self.correlation_window_seconds

    def to_dict(self) -> dict[str, Any]:
        """Serialize the annotation without causing any real-world delay."""
        return {
            "correlation_window_seconds": self.correlation_window_seconds,
            "simulated_interval_seconds": self.simulated_interval_seconds,
            "exceeds_window": self.exceeds_window,
            "rationale": self.rationale,
            "metadata_only": True,
        }


@dataclass
class AdaptivePlanner:
    """Replan from an existing plan using cumulative detection penalties."""

    environment: Environment
    cost_weight: float = 1.0
    risk_weight: float = 1.0
    technique_penalties: dict[str, float] = field(default_factory=dict)
    host_penalties: dict[str, float] = field(default_factory=dict)

    def replan(
        self,
        plan: AttackPlan,
        feedback: Iterable[DetectionFeedback],
        *,
        timing_dilation: TimingDilation | None = None,
        continue_from_current: bool = False,
    ) -> AttackPlan | None:
        """Return a lower-exposure alternative after applying feedback.

        By default replanning starts from the original plan's initial foothold,
        allowing a different route to the same objective.  Set
        ``continue_from_current`` to model planning from the plan's final state.
        Feedback penalties accumulate on this planner instance so repeated
        observations progressively discourage a technique or host.
        """
        observations = tuple(feedback)
        for observation in observations:
            if observation.technique_id is not None:
                self.technique_penalties[observation.technique_id] = (
                    self.technique_penalties.get(observation.technique_id, 0.0)
                    + observation.penalty
                )
            if observation.host is not None:
                self.host_penalties[observation.host] = (
                    self.host_penalties.get(observation.host, 0.0)
                    + observation.penalty
                )

        planner = AttackPlanner(
            self.environment,
            cost_weight=self.cost_weight,
            risk_weight=self.risk_weight,
            technique_penalties=self.technique_penalties,
            host_penalties=self.host_penalties,
        )
        state = plan.final_state if continue_from_current else plan.initial_state
        replanned = planner.plan(plan.objective, initial_state=state)
        if replanned is None:
            return None

        metadata: dict[str, Any] = {
            "adaptive": True,
            "source_weighted_score": plan.weighted_score,
            "feedback": [
                {
                    "technique_id": item.technique_id,
                    "host": item.host,
                    "confidence": item.confidence,
                    "severity": item.severity,
                    "note": item.note,
                }
                for item in observations
            ],
            "technique_penalties": dict(self.technique_penalties),
            "host_penalties": dict(self.host_penalties),
        }
        if timing_dilation is not None:
            metadata["timing_dilation"] = timing_dilation.to_dict()
        explanation = replanned.explanation + (
            "Replanned with additive penalties from simulated detection feedback.",
        )
        return replace(
            replanned,
            explanation=explanation,
            metadata=MappingProxyType(metadata),
        )


def replan_after_detection(
    environment: Environment,
    plan: AttackPlan,
    feedback: Iterable[DetectionFeedback],
    *,
    timing_dilation: TimingDilation | None = None,
    continue_from_current: bool = False,
    **planner_kwargs: Any,
) -> AttackPlan | None:
    """Convenience wrapper for a single adaptive replanning pass."""
    return AdaptivePlanner(environment, **planner_kwargs).replan(
        plan,
        feedback,
        timing_dilation=timing_dilation,
        continue_from_current=continue_from_current,
    )
