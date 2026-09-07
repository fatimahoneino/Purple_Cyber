"""PurpleForge: purple-team adversary emulation and detection validation platform.

The package couples three loops that normally live in separate teams:

* ``emulation``  -- red side. Replays adversary scenarios as synthetic telemetry.
* ``detection``  -- blue side. Evaluates Sigma-style analytics against telemetry.
* ``scoring``    -- purple side. Grades the blue side against red-side ground truth.

An ``ai`` layer sits on top to triage alerts and author new analytics for the
coverage gaps that scoring exposes.
"""

from purpleforge.models import (
    Alert,
    DetectionRule,
    Event,
    ScenarioResult,
    Severity,
    TechniqueRef,
)

__version__ = "1.0.0"

__all__ = [
    "Alert",
    "DetectionRule",
    "Event",
    "ScenarioResult",
    "Severity",
    "TechniqueRef",
    "__version__",
]
