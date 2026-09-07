"""Safe offensive simulation: environment modelling and attack-path planning."""

from purpleforge.offensive.adaptive import (
    AdaptivePlanner,
    DetectionFeedback,
    TimingDilation,
    replan_after_detection,
)
from purpleforge.offensive.environment import (
    DEFENCE_BLOCKS,
    DEFENCE_RISK,
    Credential,
    Defence,
    Edge,
    Environment,
    Host,
    build_reference_environment,
)
from purpleforge.offensive.planner import (
    TECHNIQUE_CATALOG,
    AdversaryState,
    AttackAction,
    AttackPlan,
    AttackPlanner,
    AttackTechnique,
    plan_attack,
)

__all__ = [
    "DEFENCE_BLOCKS",
    "DEFENCE_RISK",
    "TECHNIQUE_CATALOG",
    "AdaptivePlanner",
    "AdversaryState",
    "AttackAction",
    "AttackPlan",
    "AttackPlanner",
    "AttackTechnique",
    "Credential",
    "Defence",
    "DetectionFeedback",
    "Edge",
    "Environment",
    "Host",
    "TimingDilation",
    "build_reference_environment",
    "plan_attack",
    "replan_after_detection",
]
