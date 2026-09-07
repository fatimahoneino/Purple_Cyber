"""Scenario loading and validation.

A scenario is an ordered chain of ATT&CK techniques describing one intrusion.
Scenarios are declarative YAML on purpose: adding an adversary profile should
never require touching Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from purpleforge.models import TechniqueRef

SCENARIO_DIR = Path(__file__).parent / "scenarios"


@dataclass
class ScenarioStep:
    """One technique execution inside a scenario."""

    step_id: str
    technique: TechniqueRef
    description: str
    telemetry: list[dict[str, Any]]
    delay_seconds: int = 30

    def __post_init__(self) -> None:
        if not self.telemetry:
            raise ValueError(
                f"step {self.step_id} emits no telemetry; a step blue cannot "
                "possibly observe is not a useful test"
            )


@dataclass
class Scenario:
    """A full adversary emulation plan."""

    scenario_id: str
    name: str
    description: str
    threat_actor: str
    steps: list[ScenarioStep]
    references: list[str] = field(default_factory=list)

    @property
    def techniques(self) -> list[TechniqueRef]:
        """Techniques in execution order, de-duplicated."""
        seen: dict[str, TechniqueRef] = {}
        for step in self.steps:
            seen.setdefault(step.technique.technique_id, step.technique)
        return list(seen.values())

    @property
    def tactics(self) -> list[str]:
        ordered: list[str] = []
        for step in self.steps:
            if step.technique.tactic not in ordered:
                ordered.append(step.technique.tactic)
        return ordered


def _parse_step(raw: dict[str, Any], index: int) -> ScenarioStep:
    try:
        technique = TechniqueRef(
            technique_id=raw["technique_id"],
            name=raw["technique_name"],
            tactic=raw["tactic"],
        )
    except KeyError as exc:
        raise ValueError(f"step {index} is missing required key {exc.args[0]!r}") from exc

    return ScenarioStep(
        step_id=raw.get("step_id", f"step-{index:02d}"),
        technique=technique,
        description=raw.get("description", technique.name),
        telemetry=raw.get("telemetry", []),
        delay_seconds=int(raw.get("delay_seconds", 30)),
    )


def load_scenario(path: str | Path) -> Scenario:
    """Load and validate a single scenario YAML file."""
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path.name}: expected a YAML mapping at the top level")

    missing = {"scenario_id", "name", "steps"} - raw.keys()
    if missing:
        raise ValueError(f"{path.name}: missing required keys {sorted(missing)}")

    steps = [_parse_step(s, i) for i, s in enumerate(raw["steps"], start=1)]
    if not steps:
        raise ValueError(f"{path.name}: scenario has no steps")

    return Scenario(
        scenario_id=raw["scenario_id"],
        name=raw["name"],
        description=raw.get("description", ""),
        threat_actor=raw.get("threat_actor", "unattributed"),
        steps=steps,
        references=raw.get("references", []),
    )


def load_all_scenarios(directory: str | Path | None = None) -> list[Scenario]:
    """Load every scenario in a directory, sorted by id for stable output."""
    directory = Path(directory) if directory else SCENARIO_DIR
    if not directory.exists():
        return []

    scenarios: list[Scenario] = []
    for path in sorted(directory.glob("*.yml")):
        try:
            scenarios.append(load_scenario(path))
        except ValueError as exc:
            # One malformed file should not hide every other scenario.
            print(f"[warn] skipping {path.name}: {exc}")
    return sorted(scenarios, key=lambda s: s.scenario_id)
