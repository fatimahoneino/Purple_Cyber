"""Red-team layer: adversary scenario definitions and the telemetry emitter."""

from purpleforge.emulation.scenario import Scenario, ScenarioStep, load_scenario, load_all_scenarios
from purpleforge.emulation.emitter import TelemetryEmitter

__all__ = [
    "Scenario",
    "ScenarioStep",
    "TelemetryEmitter",
    "load_scenario",
    "load_all_scenarios",
]
