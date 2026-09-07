"""Environment model: the terrain an adversary reasons over.

A fixed scenario measures detection against one path. Operators take whichever path
is cheapest given what they discovered, so credentials found on one host unlock
edges elsewhere -- that is what creates non-obvious pivots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Defence(str, Enum):
    """A defensive control installed on a host."""

    EDR = "edr"
    SYSMON = "sysmon"
    APP_ALLOWLIST = "app_allowlist"
    MFA = "mfa"
    CREDENTIAL_GUARD = "credential_guard"


# Detection risk multiplier each control applies to techniques it can observe.
# EDR raises risk broadly; the others are narrow but strong against specific
# techniques, which is what makes some paths cheap and others expensive.
DEFENCE_RISK: dict[Defence, float] = {
    Defence.EDR: 1.8,
    Defence.SYSMON: 1.4,
    Defence.APP_ALLOWLIST: 2.2,
    Defence.MFA: 1.0,
    Defence.CREDENTIAL_GUARD: 1.0,
}

# Controls that block a technique outright rather than just observing it.
DEFENCE_BLOCKS: dict[Defence, set[str]] = {
    Defence.CREDENTIAL_GUARD: {"T1003.001"},
    Defence.APP_ALLOWLIST: {"T1059.001"},
    Defence.MFA: {"T1133"},
}


@dataclass(frozen=True)
class Credential:
    """A credential the operator can capture and reuse."""

    username: str
    domain: str
    is_privileged: bool = False

    @property
    def qualified(self) -> str:
        return f"{self.domain}\\{self.username}"


@dataclass
class Host:
    """One machine in the environment."""

    hostname: str
    os: str = "windows"
    value: int = 1
    defences: set[Defence] = field(default_factory=set)
    credentials: list[Credential] = field(default_factory=list)
    is_domain_controller: bool = False
    is_internet_facing: bool = False

    @property
    def risk_multiplier(self) -> float:
        """Combined observation strength of everything installed here."""
        multiplier = 1.0
        for defence in self.defences:
            multiplier *= DEFENCE_RISK.get(defence, 1.0)
        return multiplier

    def blocks(self, technique_id: str) -> bool:
        """Whether a control here prevents the technique outright."""
        base = technique_id.split(".", 1)[0]
        for defence in self.defences:
            blocked = DEFENCE_BLOCKS.get(defence, set())
            if technique_id in blocked or base in {b.split(".", 1)[0] for b in blocked}:
                return True
        return False


@dataclass(frozen=True)
class Edge:
    """Directed reachability from one host to another."""

    source: str
    target: str
    port: int = 445
    requires_privileged: bool = False


@dataclass
class Environment:
    """The full attack surface: hosts, reachability and objectives."""

    hosts: dict[str, Host] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    objectives: set[str] = field(default_factory=set)

    def add_host(self, host: Host) -> Host:
        self.hosts[host.hostname] = host
        return host

    def connect(self, source: str, target: str, **kwargs: Any) -> Edge:
        """Add a directed edge, validating both endpoints exist."""
        for name in (source, target):
            if name not in self.hosts:
                raise KeyError(f"unknown host {name!r}")
        edge = Edge(source=source, target=target, **kwargs)
        self.edges.append(edge)
        return edge

    def neighbours(self, hostname: str) -> list[Edge]:
        return [e for e in self.edges if e.source == hostname]

    @property
    def entry_points(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.is_internet_facing]

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": {
                name: {
                    "os": h.os,
                    "value": h.value,
                    "defences": sorted(d.value for d in h.defences),
                    "credentials": [c.qualified for c in h.credentials],
                    "is_domain_controller": h.is_domain_controller,
                    "is_internet_facing": h.is_internet_facing,
                    "risk_multiplier": round(h.risk_multiplier, 2),
                }
                for name, h in sorted(self.hosts.items())
            },
            "edges": [
                {"source": e.source, "target": e.target, "port": e.port}
                for e in self.edges
            ],
            "objectives": sorted(self.objectives),
        }


def build_reference_environment() -> Environment:
    """A small enterprise with deliberately uneven defensive coverage.

    The asymmetry is the point: a uniformly defended network makes every path
    equally costly and the planner's choice arbitrary. Here the jump host is well
    instrumented while the build server is not, so the cheapest route to the
    domain controller is not the shortest one.
    """
    env = Environment()
    corp = "corp.local"

    env.add_host(Host("DMZ-WEB-01", value=1, is_internet_facing=True,
                      defences={Defence.SYSMON},
                      credentials=[Credential("svc_web", corp)]))
    env.add_host(Host("JUMP-01", value=3,
                      defences={Defence.EDR, Defence.SYSMON, Defence.APP_ALLOWLIST},
                      credentials=[Credential("helpdesk", corp)]))
    # Weakly monitored but holds a privileged CI account. This is the intended
    # cheap pivot, and the reason the shortest path is not the cheapest one.
    env.add_host(Host("BUILD-01", value=4,
                      defences={Defence.SYSMON},
                      credentials=[Credential("svc_build", corp, is_privileged=True)]))
    # Expensive alternate pivot. The backup service credential makes the route
    # viable, while EDR+Sysmon make it noisier than BUILD-01. Detection feedback
    # can still push the adaptive planner here when BUILD-01 becomes too exposed.
    env.add_host(Host("FILE-01", value=6,
                      defences={Defence.EDR, Defence.SYSMON},
                      credentials=[Credential("svc_backup", corp, is_privileged=True)]))
    env.add_host(Host("DC-01", value=10, is_domain_controller=True,
                      defences={Defence.EDR, Defence.SYSMON, Defence.CREDENTIAL_GUARD},
                      credentials=[Credential("administrator", corp, is_privileged=True)]))

    env.connect("DMZ-WEB-01", "JUMP-01", port=3389)
    env.connect("DMZ-WEB-01", "BUILD-01", port=445)
    env.connect("JUMP-01", "FILE-01", port=445)
    env.connect("JUMP-01", "DC-01", port=445, requires_privileged=True)
    env.connect("BUILD-01", "FILE-01", port=445)
    env.connect("BUILD-01", "DC-01", port=445, requires_privileged=True)
    env.connect("FILE-01", "DC-01", port=445, requires_privileged=True)

    env.objectives = {"DC-01", "FILE-01"}
    return env