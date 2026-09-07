"""Tests for safe graph-based offensive planning and adaptation."""

from __future__ import annotations

import pytest

from purpleforge.offensive import (
    AdaptivePlanner,
    AdversaryState,
    AttackPlanner,
    Credential,
    Defence,
    DetectionFeedback,
    Environment,
    Host,
    TimingDilation,
    build_reference_environment,
)


def route_environment() -> Environment:
    """Two routes: a short monitored path and longer low-risk path."""
    env = Environment()
    env.add_host(Host("ENTRY", is_internet_facing=True))
    env.add_host(Host("MONITORED", defences={Defence.EDR, Defence.SYSMON, Defence.APP_ALLOWLIST}))
    env.add_host(Host("QUIET-1"))
    env.add_host(Host("QUIET-2"))
    env.add_host(Host("GOAL"))
    env.connect("ENTRY", "MONITORED")
    env.connect("MONITORED", "GOAL")
    env.connect("ENTRY", "QUIET-1")
    env.connect("QUIET-1", "QUIET-2")
    env.connect("QUIET-2", "GOAL")
    env.objectives = {"GOAL"}
    return env


def gated_environment(*, credential: bool, guarded: bool = False) -> Environment:
    env = Environment()
    credentials = [Credential("admin", "corp", is_privileged=True)] if credential else []
    defences = {Defence.CREDENTIAL_GUARD} if guarded else set()
    env.add_host(Host("ENTRY", is_internet_facing=True, credentials=credentials, defences=defences))
    env.add_host(Host("GOAL"))
    env.connect("ENTRY", "GOAL", requires_privileged=True)
    env.objectives = {"GOAL"}
    return env


class TestAttackPlanner:
    def test_cost_only_chooses_shortest_route(self):
        plan = AttackPlanner(route_environment(), cost_weight=1, risk_weight=0).plan("GOAL")
        assert plan is not None
        assert plan.hosts == ("ENTRY", "MONITORED", "GOAL")

    def test_risk_weight_can_choose_longer_safer_route(self):
        env = route_environment()
        shortest = AttackPlanner(env, cost_weight=1, risk_weight=0).plan("GOAL")
        safer = AttackPlanner(env, cost_weight=1, risk_weight=10).plan("GOAL")
        assert shortest is not None and safer is not None
        assert safer.hosts == ("ENTRY", "QUIET-1", "QUIET-2", "GOAL")
        assert safer.operational_cost > shortest.operational_cost
        assert safer.detection_risk < shortest.detection_risk
        assert safer.weighted_score == pytest.approx(
            safer.cost_weight * safer.operational_cost + safer.risk_weight * safer.detection_risk
        )

    def test_privileged_edge_is_unreachable_without_credential(self):
        assert AttackPlanner(gated_environment(credential=False)).plan("GOAL") is None

    def test_discovered_privileged_credential_unlocks_edge(self):
        plan = AttackPlanner(gated_environment(credential=True)).plan("GOAL")
        assert plan is not None
        assert [step.technique_id for step in plan.steps] == ["T1190", "T1003.001", "T1021.002"]
        assert plan.final_state.has_privileged_credential
        assert plan.steps[-1].metadata["requires_privileged"] is True

    def test_credential_guard_blocks_discovery_and_keeps_gate_closed(self):
        env = gated_environment(credential=True, guarded=True)
        assert env.hosts["ENTRY"].blocks("T1003.001")
        assert AttackPlanner(env).plan("GOAL") is None

    @pytest.mark.parametrize(
        ("defence", "blocked", "allowed"),
        [
            (Defence.APP_ALLOWLIST, "T1059.001", "T1021.002"),
            (Defence.MFA, "T1133", "T1190"),
            (Defence.CREDENTIAL_GUARD, "T1003.001", "T1021.001"),
        ],
    )
    def test_defence_blocks_only_mapped_techniques(self, defence, blocked, allowed):
        host = Host("TARGET", defences={defence})
        assert host.blocks(blocked)
        assert not host.blocks(allowed)

    def test_disconnected_objective_is_unreachable(self):
        env = Environment()
        env.add_host(Host("ENTRY", is_internet_facing=True))
        env.add_host(Host("GOAL"))
        assert AttackPlanner(env).plan("GOAL") is None

    def test_identical_inputs_produce_deterministic_plan_and_serialization(self):
        env = build_reference_environment()
        first = AttackPlanner(env, cost_weight=1, risk_weight=2).plan("DC-01")
        second = AttackPlanner(env, cost_weight=1, risk_weight=2).plan("DC-01")
        assert first is not None and second is not None
        assert first == second
        assert first.to_dict() == second.to_dict()
        assert all(step.metadata["simulation_only"] is True for step in first.steps)


class TestAdaptivePlanner:
    def test_detection_feedback_changes_route(self):
        env = build_reference_environment()
        baseline = AttackPlanner(env, cost_weight=1, risk_weight=2).plan("DC-01")
        assert baseline is not None
        adapted = AdaptivePlanner(env, cost_weight=1, risk_weight=2).replan(
            baseline, [DetectionFeedback(host="BUILD-01", severity=20)]
        )
        assert adapted is not None
        assert baseline.hosts == ("DMZ-WEB-01", "BUILD-01", "DC-01")
        assert adapted.hosts == ("DMZ-WEB-01", "JUMP-01", "FILE-01", "DC-01")
        assert adapted.metadata["adaptive"] is True

    def test_feedback_penalties_accumulate_across_replans(self):
        env = build_reference_environment()
        baseline = AttackPlanner(env, cost_weight=1, risk_weight=2).plan("DC-01")
        assert baseline is not None
        adaptive = AdaptivePlanner(env, cost_weight=1, risk_weight=2)
        feedback = DetectionFeedback(host="BUILD-01", technique_id="T1021.002", confidence=0.5, severity=4)
        first = adaptive.replan(baseline, [feedback])
        second = adaptive.replan(baseline, [feedback])
        assert first is not None and second is not None
        assert adaptive.host_penalties == {"BUILD-01": 4.0}
        assert adaptive.technique_penalties == {"T1021.002": 4.0}
        assert second.metadata["host_penalties"] == {"BUILD-01": 4.0}
        assert second.metadata["technique_penalties"] == {"T1021.002": 4.0}

    def test_timing_dilation_is_inert_metadata_only(self):
        env = build_reference_environment()
        baseline = AttackPlanner(env, cost_weight=1, risk_weight=2).plan("DC-01")
        assert baseline is not None
        control = AdaptivePlanner(env, cost_weight=1, risk_weight=2).replan(baseline, [])
        adapted = AdaptivePlanner(env, cost_weight=1, risk_weight=2).replan(
            baseline,
            [],
            timing_dilation=TimingDilation(900, 1200),
        )
        assert control is not None and adapted is not None
        assert adapted.hosts == control.hosts
        assert adapted.steps == control.steps
        assert adapted.weighted_score == control.weighted_score
        timing = adapted.metadata["timing_dilation"]
        assert timing == {
            "correlation_window_seconds": 900,
            "simulated_interval_seconds": 1200,
            "exceeds_window": True,
            "rationale": "Defensive correlation-window resilience simulation.",
            "metadata_only": True,
        }

    def test_continue_from_current_does_not_replay_completed_route(self):
        env = build_reference_environment()
        baseline = AttackPlanner(env, cost_weight=1, risk_weight=2).plan("DC-01")
        assert baseline is not None
        continued = AdaptivePlanner(env).replan(
            baseline, [DetectionFeedback(host="BUILD-01")], continue_from_current=True
        )
        assert continued is not None
        assert continued.hosts == ("DC-01",)
        assert continued.steps == ()


def test_timing_dilation_rejects_unsafe_values():
    with pytest.raises(ValueError, match="positive"):
        TimingDilation(0, 1)
    with pytest.raises(ValueError, match="non-negative"):
        TimingDilation(1, -1)
