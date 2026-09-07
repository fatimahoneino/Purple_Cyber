"""Sigma-flavoured detection engine.

Supported selection modifiers -- a deliberately small subset of Sigma, covering
the matching styles the bundled rules actually need:

=====================  ================================================
``field``              exact match, case-insensitive for strings
``field|contains``     substring
``field|startswith``   prefix
``field|endswith``     suffix
``field|re``           regular expression
``field|gt`` ``|gte``  numeric greater-than / greater-or-equal
``field|lt`` ``|lte``  numeric less-than / less-or-equal
``field|in``           membership in a list
``field|exists``       field present (or absent when ``false``)
=====================  ================================================

A list of values for one field is an OR. Multiple fields inside one selection
are an AND. That matches Sigma's semantics, which is what rule authors expect.

Conditions support ``and``, ``or``, ``not``, parentheses, and Sigma's
quantifier forms (``all of them``, ``1 of selection_*``). They are parsed with a
recursive-descent parser rather than ``eval``: rules are untrusted input because
the AI layer generates them, and handing generated strings to ``eval`` would be
a code-execution hole.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Callable, Iterable

from purpleforge.models import Alert, DetectionRule, Event, utcnow

_REGEX_CACHE: dict[str, re.Pattern[str]] = {}
_MISSING = object()


def _compile(pattern: str) -> re.Pattern[str]:
    cached = _REGEX_CACHE.get(pattern)
    if cached is None:
        cached = re.compile(pattern, re.IGNORECASE)
        _REGEX_CACHE[pattern] = cached
    return cached


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _lower(value: Any) -> str:
    return _text(value).lower()


def _numbers(actual: Any, expected: Any) -> tuple[float, float] | None:
    """Coerce both operands to float, or return ``None`` if either is not numeric."""
    try:
        return float(actual), float(expected)
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ modifiers


def _exact(actual: Any, expected: Any) -> bool:
    # Booleans first: float(True) is 1.0, which would make True == 1 match.
    if isinstance(actual, bool) or isinstance(expected, bool):
        if isinstance(expected, str):
            return _lower(actual) == _lower(expected)
        return bool(actual) is bool(expected)
    pair = _numbers(actual, expected)
    if pair is not None:
        return pair[0] == pair[1]
    return _lower(actual) == _lower(expected)


def _contains(actual: Any, expected: Any) -> bool:
    return _lower(expected) in _lower(actual)


def _startswith(actual: Any, expected: Any) -> bool:
    return _lower(actual).startswith(_lower(expected))


def _endswith(actual: Any, expected: Any) -> bool:
    return _lower(actual).endswith(_lower(expected))


def _regex(actual: Any, expected: Any) -> bool:
    return _compile(_text(expected)).search(_text(actual)) is not None


def _gt(actual: Any, expected: Any) -> bool:
    pair = _numbers(actual, expected)
    return pair is not None and pair[0] > pair[1]


def _gte(actual: Any, expected: Any) -> bool:
    pair = _numbers(actual, expected)
    return pair is not None and pair[0] >= pair[1]


def _lt(actual: Any, expected: Any) -> bool:
    pair = _numbers(actual, expected)
    return pair is not None and pair[0] < pair[1]


def _lte(actual: Any, expected: Any) -> bool:
    pair = _numbers(actual, expected)
    return pair is not None and pair[0] <= pair[1]


_MODIFIERS: dict[str, Callable[[Any, Any], bool]] = {
    "": _exact,
    "contains": _contains,
    "startswith": _startswith,
    "endswith": _endswith,
    "re": _regex,
    "gt": _gt,
    "gte": _gte,
    "lt": _lt,
    "lte": _lte,
}


class RuleSyntaxError(ValueError):
    """Raised when a rule's detection block or condition is malformed."""


# ------------------------------------------------------------ field matching


def _check_modifier(spec_key: str) -> None:
    """Raise when a field spec uses an unknown modifier.

    Checked independently of whether the field is present, because a missing field
    would otherwise short-circuit before the modifier is ever exercised. That is
    how a typo like ``|containss`` could sit in a rule looking healthy while
    silently never matching.
    """
    _, _, modifier = spec_key.partition("|")
    modifier = modifier.strip().lower()
    if modifier not in _MODIFIERS and modifier not in {"in", "exists"}:
        field = spec_key.partition("|")[0]
        raise RuleSyntaxError(f"unsupported modifier '|{modifier}' on field '{field}'")


def _match_field(spec_key: str, expected: Any, flat: dict[str, Any]) -> bool:
    field, _, modifier = spec_key.partition("|")
    modifier = modifier.strip().lower()
    _check_modifier(spec_key)
    actual = flat.get(field, _MISSING)

    if modifier == "exists":
        want = expected if isinstance(expected, bool) else _lower(expected) == "true"
        return (actual is not _MISSING) is want

    if actual is _MISSING:
        return False

    if modifier == "in":
        candidates = expected if isinstance(expected, list) else [expected]
        return any(_exact(actual, value) for value in candidates)

    matcher = _MODIFIERS[modifier]
    candidates = expected if isinstance(expected, list) else [expected]
    return any(matcher(actual, value) for value in candidates)


def _match_selection(selection: Any, flat: dict[str, Any]) -> bool:
    # A list of maps is an OR across the maps; a single map ANDs its fields.
    if isinstance(selection, list):
        return any(_match_selection(item, flat) for item in selection)
    if not isinstance(selection, dict):
        raise RuleSyntaxError(f"selection must be a mapping or list of mappings, got {type(selection).__name__}")

    # Every field spec is validated before any short-circuit, so a bad modifier in
    # a later field is still caught when an earlier one fails to match.
    for key in selection:
        _check_modifier(key)

    return all(_match_field(key, value, flat) for key, value in selection.items())


# --------------------------------------------------------- condition parsing

_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z0-9_*.]+")


class _ConditionParser:
    """Recursive-descent parser over selection names and boolean operators."""

    def __init__(
        self,
        condition: str,
        evaluate: Callable[[str], bool],
        names: Iterable[str],
    ) -> None:
        self._tokens = _TOKEN_RE.findall(condition or "")
        self._pos = 0
        self._evaluate = evaluate
        self._names = list(names)

    # -- token helpers

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _advance(self) -> str | None:
        token = self._peek()
        if token is not None:
            self._pos += 1
        return token

    # -- grammar

    def parse(self) -> bool:
        if not self._tokens:
            raise RuleSyntaxError("condition is empty")
        value = self._parse_or()
        if self._pos != len(self._tokens):
            raise RuleSyntaxError(f"unexpected token {self._peek()!r} in condition")
        return value

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while (self._peek() or "").lower() == "or":
            self._advance()
            right = self._parse_and()  # always evaluated so tokens are consumed
            value = value or right
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while (self._peek() or "").lower() == "and":
            self._advance()
            right = self._parse_not()
            value = value and right
        return value

    def _parse_not(self) -> bool:
        if (self._peek() or "").lower() == "not":
            self._advance()
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        token = self._advance()
        if token is None:
            raise RuleSyntaxError("condition ended unexpectedly")

        if token == "(":
            value = self._parse_or()
            if self._advance() != ")":
                raise RuleSyntaxError("unbalanced parentheses in condition")
            return value
        if token == ")":
            raise RuleSyntaxError("unbalanced parentheses in condition")

        lowered = token.lower()
        if (lowered in {"all", "any"} or lowered.isdigit()) and (self._peek() or "").lower() == "of":
            self._advance()
            return self._parse_quantified(lowered, self._advance())

        return self._evaluate(token)

    def _parse_quantified(self, quantifier: str, target: str | None) -> bool:
        if target is None:
            raise RuleSyntaxError(f"'{quantifier} of' is missing a target")

        if target.lower() == "them":
            targets = list(self._names)
        elif target.endswith("*"):
            prefix = target[:-1]
            targets = [n for n in self._names if n.startswith(prefix)]
        else:
            targets = [target]

        if not targets:
            raise RuleSyntaxError(f"'{quantifier} of {target}' matches no selection")

        hits = sum(1 for name in targets if self._evaluate(name))
        if quantifier == "all":
            return hits == len(targets)
        if quantifier == "any":
            return hits >= 1
        return hits >= int(quantifier)


# ---------------------------------------------------------------- the engine


class DetectionEngine:
    """Evaluates a rule set against a stream of events.

    Malformed rules are collected in :attr:`errors` and skipped rather than
    aborting the run. A broken AI-generated rule should not take down the whole
    validation pipeline, but it must not pass silently either.
    """

    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules
        self.errors: list[dict[str, str]] = []

    @property
    def enabled_rules(self) -> list[DetectionRule]:
        return [r for r in self.rules if r.enabled]

    def matches(self, rule: DetectionRule, event: Event) -> bool:
        """True when ``rule`` fires on ``event``."""
        flat = event.flatten()
        cache: dict[str, bool] = {}

        def evaluate(name: str) -> bool:
            if name not in rule.detection:
                raise RuleSyntaxError(f"condition references undefined selection '{name}'")
            if name not in cache:
                cache[name] = _match_selection(rule.detection[name], flat)
            return cache[name]

        return _ConditionParser(rule.condition, evaluate, rule.detection.keys()).parse()

    def run(self, events: list[Event]) -> list[Alert]:
        """Evaluate every enabled rule against every event.

        Returns alerts sorted by time then severity, which is the order an
        analyst would work a queue in.
        """
        alerts: list[Alert] = []
        broken: set[str] = set()

        for rule in self.enabled_rules:
            for event in events:
                if rule.rule_id in broken:
                    break
                try:
                    fired = self.matches(rule, event)
                except RuleSyntaxError as exc:
                    broken.add(rule.rule_id)
                    self.errors.append({"rule_id": rule.rule_id, "error": str(exc)})
                    break
                if fired:
                    alerts.append(
                        Alert(
                            alert_id=uuid.uuid4().hex[:12],
                            rule_id=rule.rule_id,
                            rule_title=rule.title,
                            severity=rule.severity,
                            event=event,
                            matched_at=utcnow(),
                            techniques=sorted(rule.technique_ids),
                        )
                    )

        alerts.sort(key=lambda a: (a.event.timestamp, -a.severity.rank))
        return alerts

    def validate(self) -> list[dict[str, str]]:
        """Syntax-check every rule against a probe event without running a scenario."""
        probe = Event(
            timestamp=utcnow(),
            source="probe",
            event_type="probe",
            host="probe",
            user="probe",
            fields={},
        )
        problems: list[dict[str, str]] = []
        for rule in self.rules:
            try:
                self.matches(rule, probe)
            except RuleSyntaxError as exc:
                problems.append({"rule_id": rule.rule_id, "error": str(exc)})
        return problems
