"""Adversarial robustness tests.

Two properties matter. First, the mutations must preserve semantics -- a mutation
that changed what the command does would make the whole harness invalid, since a
rule would be *right* to stop matching. Second, the hardened rules must actually
survive, which is the regression guard on the hardening work.
"""

from __future__ import annotations

import pytest

from purpleforge.detection.loader import load_all_rules
from purpleforge.emulation.emitter import TelemetryEmitter
from purpleforge.emulation.evasion import MUTATIONS, EvasionHarness, RobustnessReport
from purpleforge.emulation.scenario import load_all_scenarios
from purpleforge.models import Event, utcnow


@pytest.fixture(scope="module")
def attack_events():
    events = []
    for scenario in load_all_scenarios():
        events.extend(TelemetryEmitter(seed=1337, noise_ratio=0).emit(scenario))
    return events


@pytest.fixture(scope="module")
def report(attack_events):
    return EvasionHarness(load_all_rules(), seed=1337).run(attack_events)


def make_event(command_line: str) -> Event:
    return Event(
        timestamp=utcnow(),
        source="sysmon",
        event_type="process_creation",
        host="H1",
        user="alice",
        fields={"process.command_line": command_line, "process.name": "powershell.exe"},
        labels={"technique_id": "T1059.001"},
    )


class TestMutationSemantics:
    """Mutations must not change what the command does.

    If a mutation altered behaviour, a rule would be correct to stop matching and
    the harness would be measuring nothing.
    """

    def test_case_flip_preserves_characters(self):
        harness = EvasionHarness([], seed=1)
        original = make_event("vssadmin delete shadows /all")
        mutated = harness._mutate(original, "case_flip")
        assert (
            mutated.fields["process.command_line"].lower()
            == original.fields["process.command_line"].lower()
        )

    def test_quote_insertion_only_adds_quote_pairs(self):
        harness = EvasionHarness([], seed=1)
        original = make_event("powershell -EncodedCommand AAAA")
        mutated = harness._mutate(original, "quote_insertion")
        assert mutated.fields["process.command_line"].replace('""', "") == (
            original.fields["process.command_line"]
        )

    def test_caret_escape_only_adds_carets(self):
        harness = EvasionHarness([], seed=1)
        original = make_event("vssadmin delete shadows")
        mutated = harness._mutate(original, "caret_escape")
        assert mutated.fields["process.command_line"].replace("^", "") == (
            original.fields["process.command_line"]
        )

    def test_whitespace_padding_collapses_back(self):
        import re

        harness = EvasionHarness([], seed=1)
        original = make_event("net group Domain Admins /domain")
        mutated = harness._mutate(original, "whitespace_padding")
        assert re.sub(r"\s+", " ", mutated.fields["process.command_line"]) == (
            original.fields["process.command_line"]
        )

    def test_ground_truth_labels_survive_mutation(self):
        """Mutated events must stay attributable, or scoring breaks."""
        harness = EvasionHarness([], seed=1)
        original = make_event("powershell -enc AAAA")
        for mutation in MUTATIONS:
            mutated = harness._mutate(original, mutation)
            assert mutated.technique_id == original.technique_id
            assert mutated.is_malicious

    def test_unknown_mutation_is_rejected(self, attack_events):
        with pytest.raises(ValueError, match="unknown mutation"):
            EvasionHarness(load_all_rules()).run(attack_events, mutations=["teleport"])


class TestHardenedRules:
    """Regression guard on the rules that were hardened after the harness found them."""

    def _fires(self, rule_id: str, command_line: str, **extra) -> bool:
        from purpleforge.detection.engine import DetectionEngine

        rule = next(r for r in load_all_rules() if r.rule_id == rule_id)
        fields = {"process.command_line": command_line}
        fields.update(extra)
        event = Event(
            timestamp=utcnow(),
            source="sysmon",
            event_type="process_creation",
            host="H1",
            user="alice",
            fields=fields,
        )
        return DetectionEngine([rule]).matches(rule, event)

    def test_shadow_copy_rule_detects_the_reference_form(self):
        assert self._fires("PF-R-0003", "vssadmin.exe delete shadows /all /quiet")

    def test_shadow_copy_rule_survives_caret_escape(self):
        assert self._fires("PF-R-0003", "vssadmin.exe delete^ shadows /all /quiet")

    def test_shadow_copy_rule_survives_quote_insertion(self):
        assert self._fires("PF-R-0003", 'vssadmin.exe de""lete shadows /all /quiet')

    def test_shadow_copy_rule_survives_whitespace_padding(self):
        assert self._fires("PF-R-0003", "vssadmin.exe   delete    shadows  /all")

    def test_shadow_copy_rule_survives_case_flip(self):
        assert self._fires("PF-R-0003", "VsSaDmIn.ExE DeLeTe ShAdOwS /aLl")

    def test_shadow_copy_rule_survives_binary_rename(self):
        """Hardened to match behaviour, so renaming the binary does not help."""
        assert self._fires("PF-R-0003", "vs_helper.exe vssadmin delete shadows /all")

    def test_shadow_copy_rule_catches_bcdedit_variant(self):
        assert self._fires("PF-R-0003", "bcdedit.exe /set {default} recoveryenabled No")

    def test_shadow_copy_rule_catches_wbadmin_variant(self):
        assert self._fires("PF-R-0003", "wbadmin.exe delete catalog -quiet")

    def test_shadow_copy_rule_ignores_unrelated_commands(self):
        """Hardening must not have turned it into a catch-all."""
        assert not self._fires("PF-R-0003", "chrome.exe --type=renderer")
        assert not self._fires("PF-R-0003", "git.exe fetch --all")
        assert not self._fires("PF-R-0003", "net.exe group /domain")


class TestRobustnessReport:
    def test_score_is_a_valid_proportion(self, report):
        assert 0.0 <= report.robustness_score <= 1.0

    def test_bundled_rules_meet_a_robustness_floor(self, report):
        """Guards against a rule change that reintroduces literal matching."""
        assert report.robustness_score >= 0.85, (
            f"robustness fell to {report.robustness_score:.1%}; "
            f"fragile: {report.fragile_rules}"
        )

    def test_fragile_rules_agree_with_effective_mutations(self, report):
        """The two views must be consistent.

        effective_mutations counts distinct rules, so no mutation can claim more
        rules than appear in the fragile list.
        """
        fragile_count = len(report.fragile_rules)
        for mutation, count in report.effective_mutations.items():
            assert count <= fragile_count, f"{mutation} claims more rules than exist"

    def test_every_evasion_originally_detected(self, report):
        """Evasion is only meaningful where the rule fired to begin with."""
        assert all(r.detected_original for r in report.evasions)

    def test_rename_evasions_excluded_from_the_score(self, report):
        """Name matching is sometimes deliberate, so it is reported separately."""
        assert all(not r.identity_changing for r in report.tested)

    def test_per_rule_robustness_is_bounded(self, report):
        assert all(0.0 <= v <= 1.0 for v in report.rule_robustness.values())

    def test_empty_report_does_not_divide_by_zero(self):
        assert RobustnessReport(results=[]).robustness_score == 0.0

    def test_harness_ignores_benign_events(self):
        """Evasion is measured on attack telemetry only."""
        events = []
        for scenario in load_all_scenarios():
            events.extend(TelemetryEmitter(seed=99, noise_ratio=20).emit(scenario))
        report = EvasionHarness(load_all_rules(), seed=99).run(events)
        assert all(r.technique_id != "unknown" for r in report.results)
