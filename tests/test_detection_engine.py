"""Detection engine tests.

The engine is the component most worth testing hard: a silent matching bug would
inflate or destroy every downstream metric without any visible failure.
"""

from __future__ import annotations

import pytest

from purpleforge.detection.engine import DetectionEngine, RuleSyntaxError
from purpleforge.models import DetectionRule, Event, Severity, TechniqueRef, utcnow


def make_rule(detection: dict, condition: str, **kwargs) -> DetectionRule:
    return DetectionRule(
        rule_id=kwargs.get("rule_id", "TEST-1"),
        title="test rule",
        description="",
        severity=kwargs.get("severity", Severity.HIGH),
        techniques=kwargs.get(
            "techniques", [TechniqueRef("T1059.001", "PowerShell", "execution")]
        ),
        detection=detection,
        condition=condition,
    )


def make_event(fields: dict, **kwargs) -> Event:
    return Event(
        timestamp=utcnow(),
        source=kwargs.get("source", "sysmon"),
        event_type=kwargs.get("event_type", "process_creation"),
        host=kwargs.get("host", "WKS-1"),
        user=kwargs.get("user", "alice"),
        fields=fields,
        labels=kwargs.get("labels", {}),
    )


class TestModifiers:
    def test_exact_match_is_case_insensitive(self):
        rule = make_rule({"sel": {"process.name": "PowerShell.EXE"}}, "sel")
        event = make_event({"process.name": "powershell.exe"})
        assert DetectionEngine([rule]).matches(rule, event)

    def test_contains(self):
        rule = make_rule({"sel": {"process.command_line|contains": "-enc"}}, "sel")
        assert DetectionEngine([rule]).matches(
            rule, make_event({"process.command_line": "powershell -Enc AAA"})
        )

    def test_endswith(self):
        rule = make_rule({"sel": {"process.name|endswith": "shell.exe"}}, "sel")
        engine = DetectionEngine([rule])
        assert engine.matches(rule, make_event({"process.name": "powershell.exe"}))
        assert not engine.matches(rule, make_event({"process.name": "shell.exe.bak"}))

    def test_regex(self):
        rule = make_rule({"sel": {"process.command_line|re": r"-w\s+hidden"}}, "sel")
        assert DetectionEngine([rule]).matches(
            rule, make_event({"process.command_line": "pwsh -W  Hidden"})
        )

    def test_numeric_thresholds(self):
        rule = make_rule({"sel": {"file.modified_count|gte": 500}}, "sel")
        engine = DetectionEngine([rule])
        assert engine.matches(rule, make_event({"file.modified_count": 500}))
        assert engine.matches(rule, make_event({"file.modified_count": 9000}))
        assert not engine.matches(rule, make_event({"file.modified_count": 499}))

    def test_numeric_modifier_on_non_numeric_value_does_not_match(self):
        # Must not raise: real telemetry has inconsistent field types.
        rule = make_rule({"sel": {"file.modified_count|gte": 500}}, "sel")
        assert not DetectionEngine([rule]).matches(
            rule, make_event({"file.modified_count": "many"})
        )

    def test_in_modifier(self):
        rule = make_rule({"sel": {"process.granted_access|in": ["0x1FFFFF", "0x1410"]}}, "sel")
        engine = DetectionEngine([rule])
        assert engine.matches(rule, make_event({"process.granted_access": "0x1410"}))
        assert not engine.matches(rule, make_event({"process.granted_access": "0x1000"}))

    def test_exists_modifier(self):
        rule = make_rule({"sel": {"device.serial|exists": True}}, "sel")
        engine = DetectionEngine([rule])
        assert engine.matches(rule, make_event({"device.serial": "ABC"}))
        assert not engine.matches(rule, make_event({"other": 1}))

    def test_list_of_values_is_or(self):
        rule = make_rule({"sel": {"process.name|endswith": ["cmd.exe", "wscript.exe"]}}, "sel")
        engine = DetectionEngine([rule])
        assert engine.matches(rule, make_event({"process.name": "wscript.exe"}))
        assert not engine.matches(rule, make_event({"process.name": "chrome.exe"}))

    def test_multiple_fields_in_selection_is_and(self):
        rule = make_rule(
            {"sel": {"process.name": "net.exe", "process.parent_name": "powershell.exe"}}, "sel"
        )
        engine = DetectionEngine([rule])
        assert engine.matches(
            rule, make_event({"process.name": "net.exe", "process.parent_name": "powershell.exe"})
        )
        assert not engine.matches(
            rule, make_event({"process.name": "net.exe", "process.parent_name": "cmd.exe"})
        )

    def test_missing_field_never_matches(self):
        rule = make_rule({"sel": {"process.name": "net.exe"}}, "sel")
        assert not DetectionEngine([rule]).matches(rule, make_event({}))

    def test_boolean_is_not_confused_with_one(self):
        # float(True) == 1.0, so a naive numeric path would match here.
        rule = make_rule({"sel": {"device.first_seen": True}}, "sel")
        engine = DetectionEngine([rule])
        assert engine.matches(rule, make_event({"device.first_seen": True}))
        assert not engine.matches(rule, make_event({"device.first_seen": False}))

    def test_unknown_modifier_raises(self):
        rule = make_rule({"sel": {"process.name|bogus": "x"}}, "sel")
        with pytest.raises(RuleSyntaxError, match="unsupported modifier"):
            DetectionEngine([rule]).matches(rule, make_event({"process.name": "x"}))


class TestConditionParsing:
    def _engine_and_event(self):
        detection = {
            "a": {"process.name": "a.exe"},
            "b": {"user": "alice"},
            "c": {"host": "OTHER"},
        }
        event = make_event({"process.name": "a.exe"}, user="alice", host="WKS-1")
        return detection, event

    def test_and(self):
        detection, event = self._engine_and_event()
        rule = make_rule(detection, "a and b")
        assert DetectionEngine([rule]).matches(rule, event)

    def test_and_false_branch(self):
        detection, event = self._engine_and_event()
        rule = make_rule(detection, "a and c")
        assert not DetectionEngine([rule]).matches(rule, event)

    def test_or(self):
        detection, event = self._engine_and_event()
        rule = make_rule(detection, "c or b")
        assert DetectionEngine([rule]).matches(rule, event)

    def test_not(self):
        detection, event = self._engine_and_event()
        rule = make_rule(detection, "a and not c")
        assert DetectionEngine([rule]).matches(rule, event)

    def test_parentheses_change_precedence(self):
        detection, event = self._engine_and_event()
        # "c and (a or b)" is false because c is false; without parens
        # "c and a or b" would be true via the trailing or.
        assert not DetectionEngine([make_rule(detection, "c and (a or b)")]).matches(
            make_rule(detection, "c and (a or b)"), event
        )
        assert DetectionEngine([make_rule(detection, "c and a or b")]).matches(
            make_rule(detection, "c and a or b"), event
        )

    def test_all_of_them(self):
        detection = {"a": {"process.name": "a.exe"}, "b": {"user": "alice"}}
        event = make_event({"process.name": "a.exe"}, user="alice")
        rule = make_rule(detection, "all of them")
        assert DetectionEngine([rule]).matches(rule, event)

    def test_one_of_wildcard(self):
        detection = {
            "selection_x": {"process.name": "nope.exe"},
            "selection_y": {"user": "alice"},
        }
        event = make_event({"process.name": "a.exe"}, user="alice")
        rule = make_rule(detection, "1 of selection_*")
        assert DetectionEngine([rule]).matches(rule, event)

    def test_undefined_selection_raises(self):
        rule = make_rule({"a": {"user": "alice"}}, "a and ghost")
        with pytest.raises(RuleSyntaxError, match="undefined selection"):
            DetectionEngine([rule]).matches(rule, make_event({}, user="alice"))

    def test_unbalanced_parentheses_raises(self):
        rule = make_rule({"a": {"user": "alice"}}, "(a")
        with pytest.raises(RuleSyntaxError):
            DetectionEngine([rule]).matches(rule, make_event({}, user="alice"))

    def test_empty_condition_raises(self):
        rule = make_rule({"a": {"user": "alice"}}, "")
        with pytest.raises(RuleSyntaxError, match="empty"):
            DetectionEngine([rule]).matches(rule, make_event({}, user="alice"))

    def test_condition_is_not_evaluated_as_python(self):
        """A condition must never be executed as code.

        Rules are untrusted input because the AI layer generates them. This asserts
        the parser rejects Python syntax instead of running it.
        """
        rule = make_rule({"a": {"user": "alice"}}, "__import__('os').system('echo pwned')")
        with pytest.raises(RuleSyntaxError):
            DetectionEngine([rule]).matches(rule, make_event({}, user="alice"))


class TestEngineRun:
    def test_broken_rule_is_isolated_not_fatal(self):
        good = make_rule({"sel": {"user": "alice"}}, "sel", rule_id="GOOD")
        bad = make_rule({"sel": {"user|bogus": "alice"}}, "sel", rule_id="BAD")
        engine = DetectionEngine([bad, good])

        alerts = engine.run([make_event({}, user="alice")])

        assert [a.rule_id for a in alerts] == ["GOOD"]
        assert engine.errors and engine.errors[0]["rule_id"] == "BAD"

    def test_disabled_rules_do_not_fire(self):
        rule = make_rule({"sel": {"user": "alice"}}, "sel")
        rule.enabled = False
        assert DetectionEngine([rule]).run([make_event({}, user="alice")]) == []

    def test_validate_reports_broken_rules(self):
        bad = make_rule({"sel": {"x|nope": 1}}, "sel", rule_id="BAD")
        problems = DetectionEngine([bad]).validate()
        assert len(problems) == 1
        assert problems[0]["rule_id"] == "BAD"
