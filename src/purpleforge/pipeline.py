"""The purple-team loop orchestrator.

Wires the phases into one reproducible run:

1. **emulate** -- red generates labelled telemetry from scenario definitions
2. **detect**  -- blue evaluates the rule set against that telemetry
3. **score**   -- purple grades blue against red's ground truth
4. **triage**  -- AI ranks the alert queue by risk
5. **author**  -- AI drafts candidate analytics for the coverage gaps
6. **re-score** -- the drafts are re-tested to measure what they would recover

Step 6 is what makes the AI claim falsifiable. Generating rules is easy; showing
the coverage delta they produce against the same telemetry is the part that
demonstrates the loop actually works.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from purpleforge.ai.provider import AIProvider, get_provider
from purpleforge.ai.rule_author import DetectionAuthor
from purpleforge.ai.triage import AlertTriageAgent
from purpleforge.defensive import BehavioralBaseline, IncidentReconstructor
from purpleforge.detection.correlation import CorrelationEngine, CorrelationRule
from purpleforge.detection.correlation_loader import load_all_correlation_rules
from purpleforge.detection.engine import DetectionEngine
from purpleforge.detection.loader import load_all_rules
from purpleforge.emulation.emitter import TelemetryEmitter
from purpleforge.emulation.evasion import EvasionHarness
from purpleforge.emulation.scenario import Scenario, load_all_scenarios
from purpleforge.models import Alert, DetectionRule, Event, ScenarioResult, utcnow
from purpleforge.offensive import (
    AdaptivePlanner,
    AttackPlanner,
    DetectionFeedback,
    TimingDilation,
    build_reference_environment,
)
from purpleforge.scoring.compliance import build_compliance_report
from purpleforge.scoring.scorecard import Scorecard, build_scorecard
from purpleforge.scoring.statistics import run_stability_analysis


@dataclass
class PipelineResult:
    """Everything one full loop produced. Serialises straight into a report."""

    run_id: str
    scorecard: Scorecard
    alerts: list[Alert]
    triage_summary: dict[str, Any]
    proposed_rules: list[DetectionRule]
    rejected_proposals: list[dict[str, Any]]
    improvement: dict[str, Any]
    rule_errors: list[dict[str, str]] = field(default_factory=list)
    provider_name: str = "heuristic"
    robustness: dict[str, Any] = field(default_factory=dict)
    compliance: dict[str, Any] = field(default_factory=dict)
    stability: dict[str, Any] = field(default_factory=dict)
    attack_paths: dict[str, Any] = field(default_factory=dict)
    incidents: dict[str, Any] = field(default_factory=dict)
    behavioral: dict[str, Any] = field(default_factory=dict)

    @property
    def correlation_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if a.is_correlation]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": utcnow().isoformat(),
            "ai_provider": self.provider_name,
            **self.scorecard.to_dict(),
            "triage": self.triage_summary,
            "top_alerts": [a.to_dict() for a in self.alerts[:25]],
            "proposed_rules": [r.to_dict() for r in self.proposed_rules],
            "rejected_proposals": self.rejected_proposals,
            "improvement": self.improvement,
            "rule_errors": self.rule_errors,
            "robustness": self.robustness,
            "compliance": self.compliance,
            "stability": self.stability,
            "attack_paths": self.attack_paths,
            "incidents": self.incidents,
            "behavioral": self.behavioral,
            "correlation": {
                "rules": len(self.correlation_alerts),
                "alerts": [a.to_dict() for a in self.correlation_alerts[:10]],
            },
        }


class PurpleForgePipeline:
    """Runs the full red/blue/purple/AI loop."""

    def __init__(
        self,
        scenarios: list[Scenario] | None = None,
        rules: list[DetectionRule] | None = None,
        provider: AIProvider | None = None,
        seed: int | None = 1337,
        noise_ratio: int = 12,
        holdout_seed: int | None = None,
        correlation_rules: list[CorrelationRule] | None = None,
    ) -> None:
        self.scenarios = scenarios if scenarios is not None else load_all_scenarios()
        self.rules = rules if rules is not None else load_all_rules()
        self.correlation_rules = (
            correlation_rules if correlation_rules is not None else load_all_correlation_rules()
        )
        self.provider = provider or get_provider()
        # Base time is pinned for the whole run so every scenario and the holdout
        # share one clock, making the run reproducible from the seed alone.
        self._base_time = utcnow()
        self._base_seed = seed or 0
        self.emitter = TelemetryEmitter(
            seed=seed, noise_ratio=noise_ratio, base_time=self._base_time
        )
        # Derived from the run seed so a full run stays reproducible, while still
        # producing telemetry the generated rules have never been exposed to.
        self._holdout_seed = holdout_seed if holdout_seed is not None else (seed or 0) + 7919

    # ---------- individual phases ----------

    def emulate(self, scenario: Scenario) -> list[Event]:
        return self.emitter.emit(scenario)

    def detect(self, events: list[Event]) -> tuple[list[Alert], list[dict[str, str]]]:
        """Run single-event and correlation analytics over the same telemetry."""
        engine = DetectionEngine(self.rules)
        alerts = engine.run(events)
        errors = list(engine.errors)

        if self.correlation_rules:
            correlator = CorrelationEngine(self.correlation_rules)
            alerts.extend(correlator.run(events))
            errors.extend(correlator.errors)

        alerts.sort(key=lambda a: (a.event.timestamp, -a.severity.rank))
        return alerts, errors

    def run_scenario(self, scenario: Scenario) -> tuple[ScenarioResult, list[dict[str, str]]]:
        started = utcnow()
        events = self.emulate(scenario)
        alerts, errors = self.detect(events)
        finished = utcnow()

        result = ScenarioResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            started_at=started,
            finished_at=finished,
            events=events,
            alerts=alerts,
            techniques_executed=scenario.techniques,
        )
        return result, errors

    # ---------- the full loop ----------

    def run(
        self,
        author_rules: bool = True,
        triage_limit: int | None = 40,
        test_robustness: bool = True,
        map_compliance: bool = True,
        stability_seeds: int = 0,
        advanced_analysis: bool = True,
    ) -> PipelineResult:
        """Execute every phase and return a complete result.

        Args:
            author_rules: When False, skips AI rule generation and the re-score.
            triage_limit: Cap on alerts given full LLM treatment. See
                :meth:`AlertTriageAgent.triage`.
            test_robustness: Run the adversarial evasion harness.
            map_compliance: Derive control status for the mapped frameworks.
            stability_seeds: Number of extra seeds for confidence intervals. Zero
                skips the analysis, since it multiplies runtime by that factor.
            advanced_analysis: Build adaptive attack paths, reconstruct incidents,
                and evaluate calibrated behavioral analytics.
        """
        if not self.scenarios:
            raise RuntimeError("no scenarios loaded; nothing to emulate")
        if not self.rules:
            raise RuntimeError("no detection rules loaded; every technique would be a gap")

        runs: list[tuple[Scenario, ScenarioResult]] = []
        all_events: list[Event] = []
        all_alerts: list[Alert] = []
        rule_errors: list[dict[str, str]] = []

        for scenario in self.scenarios:
            result, errors = self.run_scenario(scenario)
            runs.append((scenario, result))
            all_events.extend(result.events)
            all_alerts.extend(result.alerts)
            rule_errors.extend(errors)

        scorecard = build_scorecard(runs)

        triage_agent = AlertTriageAgent(provider=self.provider)
        ranked = triage_agent.triage(all_alerts, limit=triage_limit)
        triage_summary = triage_agent.summarise(ranked)

        proposed: list[DetectionRule] = []
        rejected: list[dict[str, Any]] = []
        improvement: dict[str, Any] = {}

        if author_rules and scorecard.gaps:
            author = DetectionAuthor(provider=self.provider)
            proposed = author.propose_all(scorecard.gaps, all_events, self.rules)
            rejected = author.rejected
            improvement = self._measure_improvement(runs, proposed, scorecard)

        robustness: dict[str, Any] = {}
        if test_robustness:
            # Noise is irrelevant here: evasion is measured on attack events only.
            robustness = EvasionHarness(self.rules).run(
                [e for e in all_events if e.is_malicious]
            ).to_dict()

        compliance: dict[str, Any] = {}
        if map_compliance:
            compliance = build_compliance_report(scorecard).to_dict()

        stability: dict[str, Any] = {}
        if stability_seeds > 0:
            stability = self.measure_stability(stability_seeds)

        attack_paths: dict[str, Any] = {}
        incidents: dict[str, Any] = {}
        behavioral: dict[str, Any] = {}
        if advanced_analysis:
            attack_paths = self._analyse_attack_paths()
            incidents = self._reconstruct_incidents(ranked)
            behavioral = self._evaluate_behavioral(all_events)

        return PipelineResult(
            run_id=uuid.uuid4().hex[:10],
            scorecard=scorecard,
            alerts=ranked,
            triage_summary=triage_summary,
            proposed_rules=proposed,
            rejected_proposals=rejected,
            improvement=improvement,
            rule_errors=rule_errors,
            provider_name=self.provider.name,
            robustness=robustness,
            compliance=compliance,
            stability=stability,
            attack_paths=attack_paths,
            incidents=incidents,
            behavioral=behavioral,
        )

    # ---------- advanced offensive + defensive analysis ----------

    def _analyse_attack_paths(self) -> dict[str, Any]:
        """Compare the cheapest path with a detection-aware adaptive route."""
        environment = build_reference_environment()
        planner = AttackPlanner(environment, cost_weight=1.0, risk_weight=2.0)
        baseline = planner.plan("DC-01")
        if baseline is None:
            return {"error": "reference objective is unreachable"}

        # Simulated blue-team feedback: BUILD-01 generated a high-confidence
        # detection, so the operator replans rather than repeating the exposed path.
        feedback = DetectionFeedback(
            host="BUILD-01",
            confidence=1.0,
            severity=20.0,
            note="High-confidence detection on the preferred low-monitoring pivot",
        )
        adaptive = AdaptivePlanner(
            environment, cost_weight=1.0, risk_weight=2.0
        ).replan(
            baseline,
            [feedback],
            timing_dilation=TimingDilation(
                correlation_window_seconds=900,
                simulated_interval_seconds=1200,
            ),
        )

        return {
            "environment": environment.to_dict(),
            "baseline": baseline.to_dict(),
            "adaptive": adaptive.to_dict() if adaptive else None,
            "route_changed": bool(adaptive and adaptive.hosts != baseline.hosts),
            "feedback": {
                "host": feedback.host,
                "confidence": feedback.confidence,
                "severity": feedback.severity,
                "note": feedback.note,
            },
            "safety": (
                "Planning is graph simulation over ATT&CK metadata only. No commands, "
                "authentication, sockets, or attack execution occur."
            ),
        }

    @staticmethod
    def _reconstruct_incidents(alerts: list[Alert]) -> dict[str, Any]:
        """Compress an alert queue into evidence-backed incidents."""
        incidents = IncidentReconstructor().reconstruct(alerts)
        return {
            "alert_count": len(alerts),
            "incident_count": len(incidents),
            "compression_ratio": round(len(alerts) / len(incidents), 2) if incidents else 0.0,
            "incidents": [
                {
                    "incident_id": incident.incident_id,
                    "alert_count": len(incident.alerts),
                    "risk_score": incident.risk_score,
                    "confidence": incident.confidence,
                    "started_at": incident.started_at.isoformat(),
                    "ended_at": incident.ended_at.isoformat(),
                    "entities": list(incident.entities),
                    "tactic_progression": [
                        {
                            "tactic": stage.tactic,
                            "first_seen": stage.first_seen.isoformat(),
                            "techniques": list(stage.techniques),
                            "alert_ids": list(stage.alert_ids),
                        }
                        for stage in incident.tactic_progression
                    ],
                    "evidence_lineage": [
                        {
                            "alert_id": item.alert_id,
                            "rule_id": item.rule_id,
                            "event_ids": list(item.event_ids),
                            "entities": list(item.entities),
                        }
                        for item in incident.evidence_lineage
                    ],
                    # Ground truth is evaluation only; it was not used to build or
                    # rank the incident. Keeping it visibly separate makes leakage
                    # auditable rather than merely promised.
                    "evaluation": incident.evaluation(),
                }
                for incident in incidents
            ],
        }

    @staticmethod
    def _evaluate_behavioral(events: list[Event]) -> dict[str, Any]:
        """Evaluate UEBA with a benign calibration/holdout split.

        Training only on benign history is deliberate. Learning from the event being
        judged would let a slow attack poison its own baseline. Results are reported
        as measured precision/recall rather than marketing the anomaly count.
        """
        by_user: dict[str, list[Event]] = {}
        for event in sorted(events, key=lambda e: e.timestamp):
            if not event.is_malicious:
                by_user.setdefault(event.user, []).append(event)

        calibration: list[Event] = []
        benign_holdout: list[Event] = []
        for user_events in by_user.values():
            cut = max(5, int(len(user_events) * 0.7))
            calibration.extend(user_events[:cut])
            benign_holdout.extend(user_events[cut:])

        model = BehavioralBaseline(
            min_samples=5,
            threshold=4.5,
            entity_key=lambda e: f"user:{e.user}",
        )
        model.fit(calibration)
        evaluation_events = sorted(
            benign_holdout + [e for e in events if e.is_malicious],
            key=lambda e: e.timestamp,
        )
        findings = model.process(evaluation_events, learn=False)
        by_id = {e.event_id: e for e in evaluation_events}
        anomalous_ids = {f.event_id for f in findings}
        true_positive_events = sum(by_id[event_id].is_malicious for event_id in anomalous_ids)
        false_positive_events = len(anomalous_ids) - true_positive_events
        malicious_count = sum(e.is_malicious for e in evaluation_events)
        precision = (
            true_positive_events / len(anomalous_ids) if anomalous_ids else 0.0
        )
        recall = true_positive_events / malicious_count if malicious_count else 0.0

        return {
            "calibration_events": len(calibration),
            "evaluation_events": len(evaluation_events),
            "malicious_events": malicious_count,
            "findings": len(findings),
            "anomalous_events": len(anomalous_ids),
            "true_positive_events": true_positive_events,
            "false_positive_events": false_positive_events,
            "precision": round(precision, 4),
            "event_recall": round(recall, 4),
            "protocol": (
                "70% per-user benign calibration; 30% benign holdout plus all attack "
                "events; score-only evaluation prevents baseline poisoning"
            ),
            "top_findings": [
                {
                    **finding.to_dict(),
                    "ground_truth": (
                        "attack" if by_id[finding.event_id].is_malicious else "benign"
                    ),
                    "technique_id": by_id[finding.event_id].technique_id,
                }
                for finding in sorted(
                    findings,
                    key=lambda f: (not by_id[f.event_id].is_malicious, -f.score),
                )[:20]
            ],
        }

    # ---------- statistical stability ----------

    def measure_stability(self, runs: int = 12, confidence: float = 0.95) -> dict[str, Any]:
        """Re-run the assessment across seeds and report confidence intervals.

        Skips AI authoring and triage on each iteration, since only the detection
        metrics are being sampled and the AI phases would dominate runtime without
        affecting the distributions.
        """
        base_seed = self._base_seed

        def once(seed: int) -> dict[str, Any]:
            emitter = TelemetryEmitter(
                seed=seed,
                noise_ratio=self.emitter.noise_ratio,
                lookalike_rate=self.emitter.lookalike_rate,
                base_time=self._base_time,
            )
            sampled: list[tuple[Scenario, ScenarioResult]] = []
            for scenario in self.scenarios:
                events = emitter.emit(scenario)
                alerts, _ = self.detect(events)
                now = utcnow()
                sampled.append(
                    (
                        scenario,
                        ScenarioResult(
                            scenario_id=scenario.scenario_id,
                            scenario_name=scenario.name,
                            started_at=now,
                            finished_at=now,
                            events=events,
                            alerts=alerts,
                            techniques_executed=scenario.techniques,
                        ),
                    )
                )
            card = build_scorecard(sampled)
            return {
                "technique_recall": card.technique_recall,
                "precision": card.precision,
                "f1_score": card.f1_score,
                "grade": card.grade,
                "detected_techniques": card.detected_technique_ids,
                "all_techniques": {c.technique.technique_id for c in card.coverage},
            }

        # Seeds are derived deterministically from the base seed so the stability
        # analysis is itself reproducible.
        seeds = [base_seed + (i * 104_729) for i in range(runs)]
        return run_stability_analysis(once, seeds, confidence=confidence).to_dict()

    # ---------- verification of the AI contribution ----------

    def _score_with(
        self,
        rules: list[DetectionRule],
        runs: list[tuple[Scenario, ScenarioResult]],
    ) -> Scorecard:
        """Re-score existing telemetry against a different rule set."""
        rescored: list[tuple[Scenario, ScenarioResult]] = []
        for scenario, result in runs:
            alerts = DetectionEngine(rules).run(result.events)
            # Correlation rules are held constant across comparisons; varying two
            # rule sets at once would make the measured delta unattributable.
            if self.correlation_rules:
                alerts.extend(CorrelationEngine(self.correlation_rules).run(result.events))
            rescored.append(
                (
                    scenario,
                    ScenarioResult(
                        scenario_id=result.scenario_id,
                        scenario_name=result.scenario_name,
                        started_at=result.started_at,
                        finished_at=result.finished_at,
                        events=result.events,
                        alerts=alerts,
                        techniques_executed=result.techniques_executed,
                    ),
                )
            )
        return build_scorecard(rescored)

    def _holdout_runs(self, seed: int) -> list[tuple[Scenario, ScenarioResult]]:
        """Emit a fresh telemetry set from a different seed.

        Different seed means different benign noise, different lookalike placement
        and different jitter, while the attack steps stay the same. A generated
        rule that only matched a memorised noise artefact will not survive this.
        """
        emitter = TelemetryEmitter(
            seed=seed,
            noise_ratio=self.emitter.noise_ratio,
            lookalike_rate=self.emitter.lookalike_rate,
            base_time=self._base_time,
        )
        runs: list[tuple[Scenario, ScenarioResult]] = []
        for scenario in self.scenarios:
            events = emitter.emit(scenario)
            now = utcnow()
            runs.append(
                (
                    scenario,
                    ScenarioResult(
                        scenario_id=scenario.scenario_id,
                        scenario_name=scenario.name,
                        started_at=now,
                        finished_at=now,
                        events=events,
                        alerts=[],
                        techniques_executed=scenario.techniques,
                    ),
                )
            )
        return runs

    @staticmethod
    def _metrics(card: Scorecard) -> dict[str, Any]:
        return {
            "technique_recall": round(card.technique_recall, 4),
            "precision": round(card.precision, 4),
            "f1_score": round(card.f1_score, 4),
            "grade": card.grade,
            "techniques_detected": card.techniques_detected,
            "techniques_total": card.techniques_total,
            "alerts": card.total_alerts,
            "false_positives": card.false_positives,
        }

    def _measure_improvement(
        self,
        runs: list[tuple[Scenario, ScenarioResult]],
        proposed: list[DetectionRule],
        baseline: Scorecard,
    ) -> dict[str, Any]:
        """Report the coverage delta from the AI drafts, in-sample and on holdout.

        The in-sample number is optimistic by construction: the rules were drafted
        from this exact telemetry, so recovering the gap is close to guaranteed and
        proves little. The holdout number is the one worth quoting -- it re-emits
        every scenario under a different seed, so the drafts face benign noise they
        were never shown.

        The gap between the two figures is the overfitting measure. Reporting only
        the in-sample delta is how automated detection engineering gets oversold,
        so both are always emitted.

        Drafts ship disabled; they are enabled on copies here purely to measure
        their effect. Nothing on disk changes.
        """
        if not proposed:
            return {}

        candidates = [self._enabled_copy(r) for r in proposed]
        combined = self.rules + candidates

        in_sample = self._score_with(combined, runs)

        holdout_runs = self._holdout_runs(seed=self._holdout_seed)
        holdout_baseline = self._score_with(self.rules, holdout_runs)
        holdout_improved = self._score_with(combined, holdout_runs)

        # Which drafts actually generalised, and which only worked in-sample?
        in_sample_recovered = in_sample.detected_technique_ids - baseline.detected_technique_ids
        holdout_recovered = (
            holdout_improved.detected_technique_ids - holdout_baseline.detected_technique_ids
        )

        return {
            "baseline": self._metrics(baseline),
            "with_ai_rules": self._metrics(in_sample),
            "delta": {
                "technique_recall": round(in_sample.technique_recall - baseline.technique_recall, 4),
                "precision": round(in_sample.precision - baseline.precision, 4),
                "f1_score": round(in_sample.f1_score - baseline.f1_score, 4),
                "techniques_recovered": in_sample.techniques_detected - baseline.techniques_detected,
            },
            "holdout": {
                "seed": self._holdout_seed,
                "baseline": self._metrics(holdout_baseline),
                "with_ai_rules": self._metrics(holdout_improved),
                "delta": {
                    "technique_recall": round(
                        holdout_improved.technique_recall - holdout_baseline.technique_recall, 4
                    ),
                    "precision": round(
                        holdout_improved.precision - holdout_baseline.precision, 4
                    ),
                    "f1_score": round(holdout_improved.f1_score - holdout_baseline.f1_score, 4),
                    "techniques_recovered": (
                        holdout_improved.techniques_detected - holdout_baseline.techniques_detected
                    ),
                },
                "generalised": sorted(holdout_recovered),
                "in_sample_only": sorted(in_sample_recovered - holdout_recovered),
                "overfit_count": len(in_sample_recovered - holdout_recovered),
            },
            "remaining_gaps": [c.technique.technique_id for c in holdout_improved.gaps],
        }

    @staticmethod
    def _enabled_copy(rule: DetectionRule) -> DetectionRule:
        return DetectionRule(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            techniques=rule.techniques,
            detection=rule.detection,
            condition=rule.condition,
            source=rule.source,
            false_positives=rule.false_positives,
            references=rule.references,
            enabled=True,
        )
