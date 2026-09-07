"""Synthetic telemetry generation.

Design note: PurpleForge never executes attacker code. Each scenario step
declares the telemetry that the real technique *would* produce, and the emitter
renders it into normalised events tagged with red-side ground truth.

That is a deliberate trade-off. It gives up fidelity to real EDR output, and in
exchange the whole suite runs on any machine with no lab, no agents and no risk,
and every run is reproducible from a seed. For validating detection *logic* --
which is what this platform grades -- that is the right side of the trade.

Benign background noise is mixed in at a configurable ratio. Without it, a rule
matching ``*`` would score a perfect 100% and the scoring layer would be
meaningless.
"""

from __future__ import annotations

import random
from datetime import timedelta
from typing import Any, Iterator

from purpleforge.emulation.scenario import Scenario, ScenarioStep
from purpleforge.models import Event, utcnow

BENIGN_PROCESSES = [
    ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe --type=renderer"),
    ("Teams.exe", r"C:\Users\{user}\AppData\Local\Microsoft\Teams\Teams.exe"),
    ("Code.exe", r"C:\Users\{user}\AppData\Local\Programs\Microsoft VS Code\Code.exe"),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe -k netsvcs -p"),
    ("explorer.exe", r"C:\Windows\explorer.exe"),
    ("outlook.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
    ("python.exe", r"C:\Python312\python.exe manage.py runserver"),
    ("git.exe", r"C:\Program Files\Git\cmd\git.exe fetch --all"),
]

BENIGN_USERS = ["arun.k", "sneha.p", "dev.build", "helpdesk", "svc_backup"]
BENIGN_HOSTS = ["WKS-1042", "WKS-2288", "WKS-3310", "SRV-APP-02", "SRV-FILE-01"]

BENIGN_DESTINATIONS = [
    ("142.250.183.100", 443, "www.google.com"),
    ("13.107.42.14", 443, "teams.microsoft.com"),
    ("140.82.121.4", 443, "github.com"),
    ("10.20.0.15", 445, "SRV-FILE-01"),
    ("10.20.0.9", 3306, "SRV-DB-01"),
]

# Legitimate activity that resembles the behaviours the rules hunt for. These are
# the documented false positives from the rule set: backup software pruning
# snapshots, admins running PsExec, IT disabling Defender for a software test.
#
# Without these, no benign event could ever trip a rule and precision would be
# 1.0 by construction, making the scorecard meaningless. They are what force the
# rule set to earn its precision score and give the tuning backlog something real
# to work on.
BENIGN_LOOKALIKES: list[dict[str, Any]] = [
    {
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "SRV-BACKUP-01",
        "user": "svc_backup",
        "fields": {
            "process.name": "vssadmin.exe",
            "process.command_line": "vssadmin.exe delete shadows /for=D: /oldest /quiet",
            "process.parent_name": "VeeamAgent.exe",
            "process.integrity_level": "System",
        },
    },
    {
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "WKS-3310",
        "user": "helpdesk",
        "fields": {
            "process.name": "PsExec64.exe",
            "process.command_line": r"PsExec64.exe \\WKS-1042 -u corp\helpdesk -p ***** cmd /c gpupdate /force",
            "process.parent_name": "cmd.exe",
            "process.integrity_level": "High",
        },
    },
    {
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "WKS-1042",
        "user": "dev.build",
        "fields": {
            "process.name": "powershell.exe",
            "process.command_line": (
                "powershell.exe -NoP -NonI -Enc "
                "RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAEMAOgBcAGIAdQBpAGwAZAA="
            ),
            "process.parent_name": "TeamCityAgent.exe",
            "process.integrity_level": "Medium",
        },
    },
    {
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "WKS-2288",
        "user": "svc_sccm",
        "fields": {
            "process.name": "powershell.exe",
            "process.command_line": (
                'powershell.exe Add-MpPreference -ExclusionPath "D:\\SQLData" '
                "# approved CAB-4471 database exclusion"
            ),
            "process.parent_name": "CcmExec.exe",
            "process.integrity_level": "High",
        },
    },
    {
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "SRV-APP-02",
        "user": "svc_inventory",
        "fields": {
            "process.name": "net.exe",
            "process.command_line": 'net group "Domain Users" /domain',
            "process.parent_name": "powershell.exe",
            "process.integrity_level": "Medium",
        },
    },
    {
        "source": "windows_security",
        "event_type": "authentication",
        "host": "SRV-RDP-01",
        "user": "arun.k",
        "fields": {
            "winlog.event_id": 4624,
            "winlog.logon_type": 10,
            "source.ip": "10.20.4.88",
            "auth.result": "success",
        },
    },
    {
        "source": "sysmon",
        "event_type": "process_access",
        "host": "WKS-1042",
        "user": "SYSTEM",
        "fields": {
            "process.name": "MsMpEng.exe",
            "process.target_name": "lsass.exe",
            "process.granted_access": "0x1410",
            "process.call_trace": r"C:\Windows\System32\ntdll.dll+9d2e4",
        },
    },
    {
        "source": "sysmon",
        "event_type": "wmi_event",
        "host": "SRV-APP-02",
        "user": "SYSTEM",
        "fields": {
            "wmi.operation": "EventConsumerCreated",
            "wmi.consumer_name": "SCCM_RebootCoordinator",
            "process.name": "CcmExec.exe",
        },
    },
    {
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "WKS-3310",
        "user": "sneha.p",
        "fields": {
            "process.name": "7z.exe",
            "process.command_line": r"7z.exe a -mhe=on C:\Users\sneha.p\backup\notes.7z C:\Users\sneha.p\notes\*",
            "process.parent_name": "explorer.exe",
            "process.integrity_level": "Medium",
        },
    },
    {
        "source": "edr",
        "event_type": "file_modification_burst",
        "host": "SRV-FILE-01",
        "user": "svc_backup",
        "fields": {
            "process.name": "BitLockerDeploy.exe",
            "file.modified_count": 9400,
            "file.entropy_avg": 7.91,
            "time.window_seconds": 3600,
        },
    },
]


class TelemetryEmitter:
    """Renders scenario steps into normalised, ground-truth-labelled events.

    Args:
        seed: Fixes the RNG so a run can be reproduced exactly. Reports that
            cannot be reproduced are hard to act on.
        noise_ratio: Benign events generated per malicious event. The default of
            12 keeps false-positive rates in a realistic range; production SOC
            ratios are far higher, but large values slow the suite without
            changing the conclusions.
    """

    def __init__(
        self,
        seed: int | None = 1337,
        noise_ratio: int = 12,
        lookalike_rate: float = 0.08,
        base_time: datetime | None = None,
    ) -> None:
        if noise_ratio < 0:
            raise ValueError("noise_ratio cannot be negative")
        if not 0.0 <= lookalike_rate <= 1.0:
            raise ValueError("lookalike_rate must be between 0 and 1")
        self._rng = random.Random(seed)
        self.noise_ratio = noise_ratio
        self.lookalike_rate = lookalike_rate
        # Pinning base_time makes a run byte-for-byte reproducible, which is what
        # lets the test suite assert on telemetry and lets two people compare
        # results from the same seed. Left unset, timestamps track wall clock so
        # reports read naturally.
        self.base_time = base_time

    # ---------- template rendering ----------

    def _render(self, value: Any, context: dict[str, str]) -> Any:
        """Substitute ``{placeholders}`` recursively through a telemetry blob."""
        if isinstance(value, str):
            try:
                return value.format(**context)
            except (KeyError, IndexError):
                # Literal braces in a command line are common; leave them alone.
                return value
        if isinstance(value, dict):
            return {k: self._render(v, context) for k, v in value.items()}
        if isinstance(value, list):
            return [self._render(v, context) for v in value]
        return value

    def _step_events(
        self,
        step: ScenarioStep,
        scenario: Scenario,
        clock: Any,
        context: dict[str, str],
    ) -> Iterator[Event]:
        for offset, blob in enumerate(step.telemetry):
            rendered = self._render(blob, context)
            fields = {
                k: v
                for k, v in rendered.items()
                if k not in {"source", "event_type", "host", "user"}
            }
            yield Event(
                timestamp=clock + timedelta(seconds=offset * 2),
                source=rendered.get("source", "sysmon"),
                event_type=rendered.get("event_type", "process_creation"),
                host=rendered.get("host", context["host"]),
                user=rendered.get("user", context["user"]),
                fields=fields,
                labels={
                    "technique_id": step.technique.technique_id,
                    "technique_name": step.technique.name,
                    "tactic": step.technique.tactic,
                    "scenario_id": scenario.scenario_id,
                    "step_id": step.step_id,
                },
            )

    # ---------- benign noise ----------

    def _noise_event(self, clock: Any) -> Event:
        user = self._rng.choice(BENIGN_USERS)
        host = self._rng.choice(BENIGN_HOSTS)
        jitter = clock + timedelta(seconds=self._rng.randint(-120, 120))

        # A small share of noise is legitimate activity that resembles an attack.
        # No technique label, so any rule firing here is scored as a false positive.
        if self._rng.random() < self.lookalike_rate:
            blueprint = self._rng.choice(BENIGN_LOOKALIKES)
            return Event(
                timestamp=jitter,
                source=blueprint["source"],
                event_type=blueprint["event_type"],
                host=blueprint["host"],
                user=blueprint["user"],
                fields=dict(blueprint["fields"]),
            )

        if self._rng.random() < 0.7:
            name, cmdline = self._rng.choice(BENIGN_PROCESSES)
            return Event(
                timestamp=jitter,
                source="sysmon",
                event_type="process_creation",
                host=host,
                user=user,
                fields={
                    "process.name": name,
                    "process.command_line": cmdline.format(user=user),
                    "process.parent_name": "explorer.exe",
                    "process.integrity_level": "Medium",
                },
            )

        ip, port, host_header = self._rng.choice(BENIGN_DESTINATIONS)
        return Event(
            timestamp=jitter,
            source="zeek",
            event_type="network_connection",
            host=host,
            user=user,
            fields={
                "destination.ip": ip,
                "destination.port": port,
                "destination.domain": host_header,
                "network.bytes_out": self._rng.randint(400, 90_000),
                "process.name": self._rng.choice(["chrome.exe", "Teams.exe", "svchost.exe"]),
            },
        )

    # ---------- public API ----------

    def _campaign_context(self) -> dict[str, str]:
        """Pick the attacker-controlled values for this run.

        These vary with the seed. Victim identity, C2 infrastructure and staging
        paths are things a real operator changes between campaigns, so a rule that
        only matches one specific IP or filename should not be credited with
        detecting the technique. Holding these constant is what would let an
        overfit rule look like a real detection.
        """
        return {
            "user": self._rng.choice(["j.mehta", "r.iyer", "p.fernandes", "a.banerjee"]),
            "host": f"WKS-{self._rng.randint(1000, 9999)}",
            "domain": self._rng.choice(["corp.local", "ad.corp.local", "internal.corp"]),
            "c2_ip": f"{self._rng.choice([185, 45, 91, 194])}.{self._rng.randint(2, 250)}"
            f".{self._rng.randint(2, 250)}.{self._rng.randint(2, 250)}",
            "c2_domain": self._rng.choice(
                [
                    "cdn-telemetry-sync.net",
                    "static-content-delivery.org",
                    "update-checkpoint-cdn.com",
                    "metrics-collector-eu.net",
                ]
            ),
        }

    def emit(self, scenario: Scenario) -> list[Event]:
        """Generate the full event stream for one scenario, sorted by time."""
        context = self._campaign_context()
        clock = (self.base_time or utcnow()) - timedelta(hours=2)
        events: list[Event] = []

        for step in scenario.steps:
            step_events = list(self._step_events(step, scenario, clock, context))
            events.extend(step_events)

            for _ in range(self.noise_ratio * max(len(step_events), 1)):
                events.append(self._noise_event(clock))

            clock += timedelta(seconds=step.delay_seconds)

        events.sort(key=lambda e: e.timestamp)
        return events
