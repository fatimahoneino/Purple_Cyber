"""Adversarial robustness testing for detection rules.

A rule that matches the reference form of a technique but breaks under trivial
mutation provides false assurance: the coverage report shows green, and the first
operator who changes a flag walks past it.

This module applies transformations real operators use routinely -- case flipping,
inserted quotes, flag abbreviation, path padding, renamed binaries -- and reports
which rules survive. None of them change what the command *does*, so a rule that
detects the behaviour should still fire. One that stops firing was matching the
spelling, not the behaviour.

The transformations are deliberately cheap. The point is not to model an advanced
adversary; it is that a rule failing against *low-effort* evasion is not a control
worth reporting as coverage.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Any, Callable

from purpleforge.detection.engine import DetectionEngine, RuleSyntaxError
from purpleforge.models import DetectionRule, Event

# Fields worth mutating. Command lines and process names carry nearly all of the
# brittle matching in practice.
_MUTABLE_FIELDS = ("process.command_line", "process.name", "process.parent_name")


def _alternate_case(value: str, rng: random.Random) -> str:
    """Randomise case. Windows command interpretation is case-insensitive."""
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in value)


def _insert_quotes(value: str, rng: random.Random) -> str:
    """Insert empty quote pairs inside tokens.

    ``pow""ershell`` executes identically but defeats a naive substring match.
    """
    parts = value.split()
    if not parts:
        return value
    index = rng.randrange(len(parts))
    token = parts[index]
    if len(token) > 4:
        cut = rng.randrange(2, len(token) - 1)
        parts[index] = f'{token[:cut]}""{token[cut:]}'
    return " ".join(parts)


def _abbreviate_flags(value: str) -> str:
    """Shorten PowerShell flags to their minimum unique prefix.

    PowerShell accepts any unambiguous prefix, so ``-EncodedCommand``,
    ``-enc`` and ``-ec`` are equivalent. Rules pinned to one spelling miss the rest.
    """
    replacements = {
        "-EncodedCommand": "-ec",
        "-encodedcommand": "-ec",
        "-NoProfile": "-nop",
        "-noprofile": "-nop",
        "-WindowStyle Hidden": "-w hid",
        "-windowstyle hidden": "-w hid",
        "-NonInteractive": "-noni",
        "-ExecutionPolicy Bypass": "-ep bypass",
    }
    for long_form, short in replacements.items():
        value = value.replace(long_form, short)
    return value


def _pad_path(value: str) -> str:
    """Insert redundant path traversal that resolves to the same target."""
    return re.sub(
        r"([A-Za-z]:\\)(Windows\\)",
        r"\1Windows\\System32\\..\\",
        value,
        count=1,
    )


def _insert_caret(value: str, rng: random.Random) -> str:
    """Insert cmd.exe escape carets, which the shell strips before execution."""
    parts = value.split()
    if not parts:
        return value
    index = rng.randrange(len(parts))
    token = parts[index]
    if len(token) > 3:
        cut = rng.randrange(1, len(token) - 1)
        parts[index] = f"{token[:cut]}^{token[cut:]}"
    return " ".join(parts)


def _rename_binary(value: str, rng: random.Random) -> str:
    """Rename a known tool while keeping its arguments.

    Operators rename tooling as a matter of course, so a rule keyed to a binary
    name rather than its behaviour is trivially bypassed.
    """
    renames = {
        "powershell.exe": "svc_update.exe",
        "vssadmin.exe": "vs_helper.exe",
        "PsExec64.exe": "remote_admin.exe",
        "psexec.exe": "remote_admin.exe",
        "7z.exe": "archiver.exe",
        "net.exe": "netutil.exe",
        "nltest.exe": "dctest.exe",
    }
    for original, replacement in renames.items():
        if original.lower() in value.lower():
            return re.sub(re.escape(original), replacement, value, flags=re.IGNORECASE)
    return value


def _pad_whitespace(value: str, rng: random.Random) -> str:
    """Expand single spaces into runs. Argument parsers collapse them."""
    return re.sub(r" ", lambda _: " " * rng.randint(2, 4), value, count=2)


MUTATIONS: dict[str, Callable[[str, random.Random], str]] = {
    "case_flip": _alternate_case,
    "quote_insertion": _insert_quotes,
    "flag_abbreviation": lambda v, _rng: _abbreviate_flags(v),
    "path_padding": lambda v, _rng: _pad_path(v),
    "caret_escape": _insert_caret,
    "binary_rename": _rename_binary,
    "whitespace_padding": _pad_whitespace,
}

# Mutations that change which binary is named. A rule keyed to a specific tool
# name is *expected* to miss these, so they are reported separately rather than
# counted as failures -- otherwise the harness would punish rules for a design
# choice that is sometimes correct.
_IDENTITY_CHANGING = {"binary_rename"}


@dataclass
class EvasionResult:
    """Outcome of testing one rule against one mutation."""

    rule_id: str
    rule_title: str
    mutation: str
    technique_id: str
    detected_original: bool
    detected_mutated: bool

    @property
    def evaded(self) -> bool:
        """True when the mutation defeated a rule that originally fired."""
        return self.detected_original and not self.detected_mutated

    @property
    def identity_changing(self) -> bool:
        return self.mutation in _IDENTITY_CHANGING

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "mutation": self.mutation,
            "technique_id": self.technique_id,
            "detected_original": self.detected_original,
            "detected_mutated": self.detected_mutated,
            "evaded": self.evaded,
            "identity_changing": self.identity_changing,
        }


@dataclass
class RobustnessReport:
    """Aggregate adversarial robustness across a rule set."""

    results: list[EvasionResult]

    @property
    def behavioural(self) -> list[EvasionResult]:
        """Results excluding mutations that rename the binary."""
        return [r for r in self.results if not r.identity_changing]

    @property
    def tested(self) -> list[EvasionResult]:
        """Cases where the rule fired on the original, so evasion is measurable."""
        return [r for r in self.behavioural if r.detected_original]

    @property
    def evasions(self) -> list[EvasionResult]:
        return [r for r in self.tested if r.evaded]

    @property
    def robustness_score(self) -> float:
        """Share of measurable (rule, mutation, event) cases that survived mutation.

        Event-level on purpose. A rule that survives a mutation on one command line
        but not another is genuinely partially fragile, and a rule-level score would
        round that to either fully robust or fully broken.
        """
        if not self.tested:
            return 0.0
        return 1.0 - (len(self.evasions) / len(self.tested))

    @property
    def rule_robustness(self) -> dict[str, float]:
        """Per-rule survival rate, for ranking the hardening backlog."""
        totals: dict[str, list[int]] = {}
        for result in self.tested:
            entry = totals.setdefault(result.rule_id, [0, 0])
            entry[0] += 1
            entry[1] += int(not result.evaded)
        return {
            rule_id: survived / total
            for rule_id, (total, survived) in sorted(totals.items())
        }

    @property
    def fragile_rules(self) -> dict[str, list[str]]:
        """Rules mapped to the mutations that defeated them."""
        fragile: dict[str, list[str]] = {}
        for result in self.evasions:
            fragile.setdefault(result.rule_id, []).append(result.mutation)
        return {k: sorted(set(v)) for k, v in sorted(fragile.items())}

    @property
    def effective_mutations(self) -> dict[str, int]:
        """Mutations ranked by the number of *distinct rules* they defeated.

        Counts unique rules rather than evasion events. A rule with several
        matching events would otherwise be counted once per event, inflating the
        apparent reach of a mutation and disagreeing with the fragile-rule list.
        """
        by_mutation: dict[str, set[str]] = {}
        for result in self.evasions:
            by_mutation.setdefault(result.mutation, set()).add(result.rule_id)
        return dict(
            sorted(
                ((m, len(rules)) for m, rules in by_mutation.items()),
                key=lambda kv: (-kv[1], kv[0]),
            )
        )

    @property
    def rename_evasions(self) -> list[str]:
        """Rules defeated by renaming the binary, reported separately."""
        return sorted(
            {r.rule_id for r in self.results if r.identity_changing and r.evaded}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "robustness_score": round(self.robustness_score, 4),
            "cases_tested": len(self.tested),
            "evasions_found": len(self.evasions),
            "fragile_rules": self.fragile_rules,
            "effective_mutations": self.effective_mutations,
            "rule_robustness": {k: round(v, 3) for k, v in self.rule_robustness.items()},
            "name_dependent_rules": self.rename_evasions,
            "results": [r.to_dict() for r in self.evasions],
        }


class EvasionHarness:
    """Mutates attack telemetry and measures which rules survive."""

    def __init__(self, rules: list[DetectionRule], seed: int = 4242) -> None:
        self.rules = [r for r in rules if r.enabled]
        self._rng = random.Random(seed)

    def _mutate(self, event: Event, mutation: str) -> Event:
        """Apply one mutation to an event's mutable string fields."""
        transform = MUTATIONS[mutation]
        fields = dict(event.fields)

        for field_name in _MUTABLE_FIELDS:
            value = fields.get(field_name)
            if isinstance(value, str) and value:
                fields[field_name] = transform(value, self._rng)

        return Event(
            timestamp=event.timestamp,
            source=event.source,
            event_type=event.event_type,
            host=event.host,
            user=event.user,
            fields=fields,
            labels=dict(event.labels),
        )

    def run(self, events: list[Event], mutations: list[str] | None = None) -> RobustnessReport:
        """Test every rule against every mutation of every malicious event."""
        selected = mutations or list(MUTATIONS)
        unknown = set(selected) - set(MUTATIONS)
        if unknown:
            raise ValueError(f"unknown mutation(s): {sorted(unknown)}")

        malicious = [e for e in events if e.is_malicious]
        engine = DetectionEngine(self.rules)
        results: list[EvasionResult] = []

        for rule in self.rules:
            for event in malicious:
                try:
                    original = engine.matches(rule, event)
                except RuleSyntaxError:
                    break  # broken rule; the engine reports it separately
                if not original:
                    continue  # nothing to evade

                for mutation in selected:
                    mutated = self._mutate(event, mutation)
                    try:
                        still_detected = engine.matches(rule, mutated)
                    except RuleSyntaxError:
                        continue
                    results.append(
                        EvasionResult(
                            rule_id=rule.rule_id,
                            rule_title=rule.title,
                            mutation=mutation,
                            technique_id=event.technique_id or "unknown",
                            detected_original=True,
                            detected_mutated=still_detected,
                        )
                    )

        return RobustnessReport(results=results)
