"""Safe, explainable attack-path planning over a modelled environment.

This module contains metadata and graph-search logic only.  It never opens a
socket, invokes a command, authenticates to a service, or executes a technique.
ATT&CK identifiers describe simulated transitions so defenders can reason about
coverage without turning a plan into executable tradecraft.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import heapq
import itertools
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from purpleforge.offensive.environment import Credential, Edge, Environment, Host


@dataclass(frozen=True)
class AttackTechnique:
    """Non-executable ATT&CK technique metadata used to score a transition."""

    technique_id: str
    name: str
    tactic: str
    summary: str
    operational_cost: float
    detection_risk: float
    ports: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.operational_cost < 0 or self.detection_risk < 0:
            raise ValueError("technique cost and risk must be non-negative")


_TECHNIQUES = {
    "T1190": AttackTechnique(
        "T1190", "Exploit Public-Facing Application", "initial-access",
        "Simulates an initial foothold on an exposed host.", 3.0, 0.55,
    ),
    "T1078": AttackTechnique(
        "T1078", "Valid Accounts", "lateral-movement",
        "Simulates credential-backed access over a modelled edge.", 1.0, 0.30,
    ),
    "T1021.001": AttackTechnique(
        "T1021.001", "Remote Services: RDP", "lateral-movement",
        "Labels movement over a modelled RDP edge.", 1.3, 0.45, (3389,),
    ),
    "T1021.002": AttackTechnique(
        "T1021.002", "Remote Services: SMB/Windows Admin Shares",
        "lateral-movement", "Labels movement over a modelled SMB edge.",
        1.1, 0.50, (445,),
    ),
    "T1003.001": AttackTechnique(
        "T1003.001", "OS Credential Dumping: LSASS Memory",
        "credential-access", "Simulates discovery of credentials on a host.",
        2.0, 0.80,
    ),
}

#: Read-only safe technique catalog.  Entries contain descriptive metadata only.
TECHNIQUE_CATALOG: Mapping[str, AttackTechnique] = MappingProxyType(_TECHNIQUES)


@dataclass(frozen=True)
class AdversaryState:
    """Planner state: current host, controlled hosts, and known credentials."""

    current_host: str
    controlled_hosts: frozenset[str] = field(default_factory=frozenset)
    credentials: frozenset[Credential] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.current_host:
            raise ValueError("current_host cannot be empty")
        if self.current_host not in self.controlled_hosts:
            object.__setattr__(
                self, "controlled_hosts", self.controlled_hosts | {self.current_host}
            )

    @property
    def has_privileged_credential(self) -> bool:
        """Return whether any credential can satisfy a privileged edge."""
        return any(credential.is_privileged for credential in self.credentials)


@dataclass(frozen=True)
class AttackAction:
    """One simulated state transition and its explainable scoring inputs."""

    technique: AttackTechnique
    source_host: str | None
    target_host: str
    operational_cost: float
    detection_risk: float
    acquired_credentials: tuple[Credential, ...] = ()
    rationale: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def technique_id(self) -> str:
        """Convenience access to the ATT&CK identifier."""
        return self.technique.technique_id


@dataclass(frozen=True)
class AttackPlan:
    """An immutable, explainable sequence of simulated attack actions."""

    initial_state: AdversaryState
    final_state: AdversaryState
    objective: str
    steps: tuple[AttackAction, ...]
    operational_cost: float
    detection_risk: float
    weighted_score: float
    cost_weight: float
    risk_weight: float
    explanation: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def cost(self) -> float:
        """Alias for total operational cost for concise consumer access."""
        return self.operational_cost

    @property
    def risk(self) -> float:
        """Alias for total detection risk for concise consumer access."""
        return self.detection_risk

    @property
    def hosts(self) -> tuple[str, ...]:
        """Return distinct consecutive hosts in traversal order."""
        traversed = [self.initial_state.current_host]
        for step in self.steps:
            if step.target_host != traversed[-1]:
                traversed.append(step.target_host)
        return tuple(traversed)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the plan to plain data suitable for reports or APIs."""
        return {
            "objective": self.objective,
            "hosts": list(self.hosts),
            "operational_cost": self.operational_cost,
            "detection_risk": self.detection_risk,
            "weighted_score": self.weighted_score,
            "steps": [
                {
                    "technique_id": step.technique_id,
                    "technique": step.technique.name,
                    "source_host": step.source_host,
                    "target_host": step.target_host,
                    "operational_cost": step.operational_cost,
                    "detection_risk": step.detection_risk,
                    "rationale": step.rationale,
                    "metadata": dict(step.metadata),
                }
                for step in self.steps
            ],
            "explanation": list(self.explanation),
            "metadata": dict(self.metadata),
        }


class AttackPlanner:
    """Dijkstra/A* planner minimizing weighted cost and detection risk.

    ``technique_penalties`` and ``host_penalties`` are additive weighted-score
    penalties.  They are primarily intended for adaptive replanning after
    simulated detection feedback.  The optional heuristic must be admissible to
    retain A* optimality; the default zero heuristic gives Dijkstra's algorithm.
    """

    def __init__(
        self,
        environment: Environment,
        *,
        cost_weight: float = 1.0,
        risk_weight: float = 1.0,
        technique_penalties: Mapping[str, float] | None = None,
        host_penalties: Mapping[str, float] | None = None,
    ) -> None:
        if cost_weight < 0 or risk_weight < 0:
            raise ValueError("planning weights must be non-negative")
        if cost_weight == risk_weight == 0:
            raise ValueError("at least one planning weight must be positive")
        self.environment = environment
        self.cost_weight = cost_weight
        self.risk_weight = risk_weight
        self.technique_penalties = dict(technique_penalties or {})
        self.host_penalties = dict(host_penalties or {})
        if any(value < 0 for value in self.technique_penalties.values()):
            raise ValueError("technique penalties must be non-negative")
        if any(value < 0 for value in self.host_penalties.values()):
            raise ValueError("host penalties must be non-negative")

    def plan(
        self,
        objective: str,
        *,
        initial_state: AdversaryState | None = None,
        entry_hosts: Iterable[str] | None = None,
        heuristic: Mapping[str, float] | None = None,
    ) -> AttackPlan | None:
        """Find the lowest weighted-score plan to ``objective``.

        When no explicit state is supplied, all internet-facing hosts are
        candidate initial footholds.  Each is modelled as a safe initial-access
        transition.  Return ``None`` when defenses or credential gates make the
        objective unreachable.
        """
        if objective not in self.environment.hosts:
            raise KeyError(f"unknown objective host {objective!r}")
        estimates = dict(heuristic or {})
        if any(value < 0 for value in estimates.values()):
            raise ValueError("heuristic values must be non-negative")

        starts = self._initial_candidates(initial_state, entry_hosts)
        queue: list[tuple[float, int, float, float, AdversaryState, tuple[AttackAction, ...]]] = []
        counter = itertools.count()
        best: dict[AdversaryState, float] = {}
        for state, steps, cost, risk in starts:
            score = self._score(cost, risk, steps[-1] if steps else None)
            best[state] = score
            heapq.heappush(
                queue,
                (score + estimates.get(state.current_host, 0.0), next(counter),
                 cost, risk, state, steps),
            )

        while queue:
            _, _, cost, risk, state, steps = heapq.heappop(queue)
            score = self._path_score(cost, risk, steps)
            if score > best.get(state, float("inf")):
                continue
            if state.current_host == objective:
                return self._make_plan(objective, starts, state, steps, cost, risk)
            for action, next_state in self._actions(state):
                next_steps = steps + (action,)
                next_cost = cost + action.operational_cost
                next_risk = risk + action.detection_risk
                next_score = self._path_score(next_cost, next_risk, next_steps)
                if next_score >= best.get(next_state, float("inf")):
                    continue
                best[next_state] = next_score
                heapq.heappush(
                    queue,
                    (next_score + estimates.get(next_state.current_host, 0.0),
                     next(counter), next_cost, next_risk, next_state, next_steps),
                )
        return None

    def _initial_candidates(
        self,
        initial_state: AdversaryState | None,
        entry_hosts: Iterable[str] | None,
    ) -> list[tuple[AdversaryState, tuple[AttackAction, ...], float, float]]:
        if initial_state is not None:
            if entry_hosts is not None:
                raise ValueError("initial_state and entry_hosts are mutually exclusive")
            if initial_state.current_host not in self.environment.hosts:
                raise KeyError(f"unknown initial host {initial_state.current_host!r}")
            return [(initial_state, (), 0.0, 0.0)]

        names = list(entry_hosts) if entry_hosts is not None else [
            host.hostname for host in self.environment.entry_points
        ]
        if len(names) != len(set(names)):
            names = list(dict.fromkeys(names))
        if not names:
            raise ValueError("no initial state or entry hosts are available")
        candidates = []
        technique = TECHNIQUE_CATALOG["T1190"]
        for name in names:
            host = self._host(name)
            if host.blocks(technique.technique_id):
                continue
            state = AdversaryState(name)
            risk = technique.detection_risk * host.risk_multiplier
            action = AttackAction(
                technique, None, name, technique.operational_cost, risk,
                tuple(state.credentials),
                "Modelled initial access to an explicitly exposed entry host.",
                MappingProxyType({"simulation_only": True}),
            )
            candidates.append((state, (action,), action.operational_cost, risk))
        return candidates


    def _actions(self, state: AdversaryState) -> Iterable[tuple[AttackAction, AdversaryState]]:
        host = self._host(state.current_host)
        acquired_here = self._discoverable_credentials(host, state)
        if acquired_here:
            discovery = TECHNIQUE_CATALOG["T1003.001"]
            risk = discovery.detection_risk * host.risk_multiplier
            next_state = AdversaryState(
                state.current_host,
                state.controlled_hosts,
                state.credentials | frozenset(acquired_here),
            )
            yield AttackAction(
                discovery, state.current_host, state.current_host,
                discovery.operational_cost, risk, acquired_here,
                "Simulated credential discovery on the controlled host.",
                MappingProxyType({"simulation_only": True}),
            ), next_state

        for edge in self.environment.neighbours(state.current_host):
            if edge.requires_privileged and not state.has_privileged_credential:
                continue
            target = self._host(edge.target)
            technique = self._technique_for_edge(edge)
            if target.blocks(technique.technique_id):
                continue
            acquired: tuple[Credential, ...] = ()
            next_state = AdversaryState(
                edge.target,
                state.controlled_hosts | {edge.target},
                state.credentials,
            )
            risk = technique.detection_risk * target.risk_multiplier
            gate = "privileged credential satisfied" if edge.requires_privileged else "no privileged credential required"
            action = AttackAction(
                technique, edge.source, edge.target,
                technique.operational_cost, risk,
                acquired,
                f"Modelled edge {edge.source} -> {edge.target} on port {edge.port}; {gate}.",
                MappingProxyType({
                    "port": edge.port,
                    "requires_privileged": edge.requires_privileged,
                    "simulation_only": True,
                }),
            )
            yield action, next_state

    def _technique_for_edge(self, edge: Edge) -> AttackTechnique:
        for technique_id in ("T1021.001", "T1021.002"):
            technique = TECHNIQUE_CATALOG[technique_id]
            if edge.port in technique.ports:
                return technique
        return TECHNIQUE_CATALOG["T1078"]

    @staticmethod
    def _discoverable_credentials(
        host: Host, state: AdversaryState
    ) -> tuple[Credential, ...]:
        """Return credentials exposed by the model unless a defense blocks it."""
        discovery = TECHNIQUE_CATALOG["T1003.001"]
        if host.blocks(discovery.technique_id):
            return ()
        return tuple(
            credential for credential in host.credentials
            if credential not in state.credentials
        )

    def _host(self, hostname: str) -> Host:
        try:
            return self.environment.hosts[hostname]
        except KeyError as error:
            raise KeyError(f"unknown host {hostname!r}") from error

    def _score(
        self, cost: float, risk: float, action: AttackAction | None = None
    ) -> float:
        score = self.cost_weight * cost + self.risk_weight * risk
        if action is not None:
            score += self.technique_penalties.get(action.technique_id, 0.0)
            score += self.host_penalties.get(action.target_host, 0.0)
        return score

    def _path_score(
        self, cost: float, risk: float, steps: tuple[AttackAction, ...]
    ) -> float:
        return self.cost_weight * cost + self.risk_weight * risk + sum(
            self.technique_penalties.get(step.technique_id, 0.0)
            + self.host_penalties.get(step.target_host, 0.0)
            for step in steps
        )

    def _make_plan(
        self,
        objective: str,
        starts: list[tuple[AdversaryState, tuple[AttackAction, ...], float, float]],
        final_state: AdversaryState,
        steps: tuple[AttackAction, ...],
        cost: float,
        risk: float,
    ) -> AttackPlan:
        first_host = next(
            (step.target_host for step in steps if step.source_host is None), None
        )
        initial = next(
            (candidate[0] for candidate in starts
             if first_host is None or candidate[0].current_host == first_host),
            starts[0][0],
        )
        weighted = self._path_score(cost, risk, steps)
        explanations = tuple(
            f"{index}. {step.technique_id} {step.technique.name}: {step.rationale} "
            f"cost={step.operational_cost:.2f}, risk={step.detection_risk:.2f}"
            for index, step in enumerate(steps, 1)
        ) + (
            f"Selected weighted score {weighted:.2f} = "
            f"{self.cost_weight:.2f}*cost + {self.risk_weight:.2f}*risk + penalties.",
        )
        return AttackPlan(
            initial, final_state, objective, steps, cost, risk, weighted,
            self.cost_weight, self.risk_weight, explanations,
        )


def plan_attack(
    environment: Environment,
    objective: str,
    **kwargs: Any,
) -> AttackPlan | None:
    """Convenience wrapper that constructs :class:`AttackPlanner` and plans.

    Planner-constructor options are accepted as keyword arguments.  For advanced
    initial-state or A* heuristic configuration, instantiate ``AttackPlanner``
    directly so the two categories of options remain explicit.
    """
    return AttackPlanner(environment, **kwargs).plan(objective)
