"""Command-line interface.

Subcommands:

* ``run``       -- full loop: emulate, detect, score, triage, author, report
* ``scenarios`` -- list available adversary scenarios
* ``rules``     -- list and syntax-check the detection rule set
* ``validate``  -- CI gate: fail the build when coverage regresses
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

from purpleforge import __version__
from purpleforge.ai.provider import get_provider
from purpleforge.ai.rule_author import DetectionAuthor
from purpleforge.detection.engine import DetectionEngine
from purpleforge.detection.loader import load_all_rules
from purpleforge.emulation.scenario import load_all_scenarios
from purpleforge.pipeline import PurpleForgePipeline
from purpleforge.reporting.console import render_console
from purpleforge.reporting.html import render_html
from purpleforge.reporting.navigator import build_navigator_layer

console = Console()


# --------------------------------------------------------------------- run


def _cmd_run(args: argparse.Namespace) -> int:
    scenarios = load_all_scenarios(args.scenario_dir) if args.scenario_dir else load_all_scenarios()
    if args.scenario:
        wanted = {s.lower() for s in args.scenario}
        scenarios = [
            s
            for s in scenarios
            if s.scenario_id.lower() in wanted or s.name.lower() in wanted
        ]
        if not scenarios:
            console.print(f"[red]No scenario matched {args.scenario}[/red]")
            return 2

    rules = load_all_rules(args.rule_dir) if args.rule_dir else load_all_rules()
    provider = get_provider(prefer_llm=not args.no_ai)

    if provider.is_llm:
        console.print(f"[dim]Using LLM provider ({provider.model}) for triage and rule drafting[/dim]")
    else:
        console.print("[dim]No OPENAI_API_KEY set; using the local heuristic engine[/dim]")

    pipeline = PurpleForgePipeline(
        scenarios=scenarios,
        rules=rules,
        provider=provider,
        seed=args.seed,
        noise_ratio=args.noise,
    )

    if args.stability:
        console.print(f"[dim]Sampling {args.stability} seeds for confidence intervals[/dim]")

    try:
        result = pipeline.run(
            author_rules=not args.no_author,
            triage_limit=args.triage_limit,
            test_robustness=not args.no_robustness,
            map_compliance=not args.no_compliance,
            stability_seeds=args.stability,
            advanced_analysis=not args.no_advanced,
        )
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    render_console(result, console)
    payload = result.to_dict()
    outdir = Path(args.output)

    if args.html:
        path = render_html(payload, outdir / f"report-{result.run_id}.html")
        console.print(f"[green]HTML report[/green]  {path}")

    if args.json:
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir / f"result-{result.run_id}.json"
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]JSON result[/green]  {path}")

    if args.navigator:
        outdir.mkdir(parents=True, exist_ok=True)
        layer = build_navigator_layer(result.scorecard)
        path = outdir / f"navigator-{result.run_id}.json"
        path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
        console.print(f"[green]ATT&CK Navigator layer[/green]  {path}")
        console.print("[dim]  Open at https://mitre-attack.github.io/attack-navigator/ via 'Open Existing Layer'[/dim]")

    if args.write_rules and result.proposed_rules:
        written = DetectionAuthor.write(result.proposed_rules, args.write_rules)
        console.print(
            f"[green]{len(written)} draft rule(s)[/green] written to {args.write_rules} "
            "[dim](disabled, pending review)[/dim]"
        )

    return 0


# --------------------------------------------------------------- scenarios


def _cmd_scenarios(args: argparse.Namespace) -> int:
    from rich.table import Table

    from purpleforge.reporting.console import _supports_unicode

    arrow = " -> " if not _supports_unicode() else " → "
    scenarios = load_all_scenarios(args.scenario_dir) if args.scenario_dir else load_all_scenarios()
    if not scenarios:
        console.print("[yellow]No scenarios found[/yellow]")
        return 1

    table = Table(title="Adversary Emulation Scenarios", expand=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Threat Actor", style="magenta")
    table.add_column("Steps", justify="right")
    table.add_column("Techniques", justify="right")
    table.add_column("Tactics", style="dim")

    for scenario in scenarios:
        table.add_row(
            scenario.scenario_id,
            scenario.name,
            scenario.threat_actor,
            str(len(scenario.steps)),
            str(len(scenario.techniques)),
            arrow.join(scenario.tactics),
        )
    console.print(table)
    return 0


# ------------------------------------------------------------------- rules


def _cmd_rules(args: argparse.Namespace) -> int:
    from rich.table import Table

    rules = load_all_rules(args.rule_dir) if args.rule_dir else load_all_rules()
    if not rules:
        console.print("[yellow]No rules found[/yellow]")
        return 1

    problems = DetectionEngine(rules).validate()

    table = Table(title="Detection Rules", expand=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title")
    table.add_column("Severity", justify="center")
    table.add_column("Techniques", style="dim")
    table.add_column("Source", style="dim")
    table.add_column("Status", justify="center")

    broken = {p["rule_id"] for p in problems}
    for rule in rules:
        ok = rule.rule_id not in broken
        status = "[green]ok[/green]" if ok else "[red]invalid[/red]"
        if not rule.enabled:
            status = "[yellow]disabled[/yellow]"
        table.add_row(
            rule.rule_id,
            rule.title,
            rule.severity.value,
            ", ".join(sorted(rule.technique_ids)) or "-",
            rule.source,
            status,
        )
    console.print(table)

    if problems:
        console.print("\n[bold red]Invalid rules[/bold red]")
        for problem in problems:
            console.print(f"  {problem['rule_id']}: {problem['error']}")
        return 1

    console.print(f"\n[green]All {len(rules)} rules parsed successfully[/green]")
    return 0


# -------------------------------------------------------------- robustness


def _cmd_robustness(args: argparse.Namespace) -> int:
    """Adversarial evasion testing against the detection rule set."""
    from rich.table import Table

    from purpleforge.emulation.emitter import TelemetryEmitter
    from purpleforge.emulation.evasion import MUTATIONS, EvasionHarness

    rules = load_all_rules(args.rule_dir) if args.rule_dir else load_all_rules()
    if not rules:
        console.print("[yellow]No rules found[/yellow]")
        return 1

    events = []
    for scenario in load_all_scenarios():
        events.extend(TelemetryEmitter(seed=args.seed, noise_ratio=0).emit(scenario))

    try:
        report = EvasionHarness(rules, seed=args.seed).run(events, mutations=args.mutation)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        console.print(f"[dim]Available mutations: {', '.join(sorted(MUTATIONS))}[/dim]")
        return 2

    score = report.robustness_score
    style = "green" if score >= 0.9 else "yellow" if score >= 0.75 else "red"
    console.print(
        f"\n[bold]Adversarial robustness[/bold]  "
        f"[{style}]{score:.1%}[/{style}]  "
        f"[dim]({len(report.evasions)} evasions across {len(report.tested)} cases)[/dim]\n"
    )
    console.print(
        "[dim]Mutations preserve what the command does. A rule that stops firing was\n"
        "matching the spelling of the technique rather than the behaviour.[/dim]\n"
    )

    if report.effective_mutations:
        table = Table(title="Mutations by Rules Defeated", expand=True)
        table.add_column("Mutation", style="cyan")
        table.add_column("Rules defeated", justify="right", style="red")
        for mutation, count in report.effective_mutations.items():
            table.add_row(mutation, str(count))
        console.print(table)
        console.print()

    if report.fragile_rules:
        survival = report.rule_robustness
        table = Table(title="Fragile Rules (hardening backlog)", expand=True)
        table.add_column("Rule", style="cyan")
        table.add_column("Survival", justify="right")
        table.add_column("Defeated by", style="red")
        # Weakest rules first: that is the order to work the backlog in.
        for rule_id, mutations in sorted(
            report.fragile_rules.items(), key=lambda kv: survival.get(kv[0], 0.0)
        ):
            rate = survival.get(rule_id, 0.0)
            style = "green" if rate >= 0.9 else "yellow" if rate >= 0.7 else "red"
            table.add_row(rule_id, f"[{style}]{rate:.0%}[/{style}]", ", ".join(mutations))
        console.print(table)
        console.print()
    else:
        console.print("[green]No rule was defeated by behaviour-preserving mutation[/green]\n")

    if report.rename_evasions:
        console.print(
            "[yellow]Name-dependent rules[/yellow] "
            f"[dim](evaded by renaming the binary): {', '.join(report.rename_evasions)}[/dim]"
        )
        console.print(
            "[dim]Reported separately: matching on tool name is sometimes a deliberate\n"
            "choice, so this is not counted against the robustness score.[/dim]\n"
        )

    return 0


# -------------------------------------------------------------- compliance


def _cmd_compliance(args: argparse.Namespace) -> int:
    """Map measured detection coverage onto control frameworks."""
    from rich.table import Table

    from purpleforge.scoring.compliance import build_compliance_report

    pipeline = PurpleForgePipeline(
        provider=get_provider(prefer_llm=False), seed=args.seed, noise_ratio=args.noise
    )
    try:
        result = pipeline.run(
            author_rules=False, triage_limit=0, test_robustness=False, map_compliance=False
        )
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    report = build_compliance_report(result.scorecard)
    payload = report.to_dict()

    console.print("\n[bold]Control Effectiveness from Adversary Emulation[/bold]\n")
    console.print(f"[dim]{payload['scope_note']}[/dim]\n")

    _STATUS = {
        "effective": "[green]effective[/green]",
        "partially_effective": "[yellow]partial[/yellow]",
        "ineffective": "[red]ineffective[/red]",
        "not_assessed": "[dim]not assessed[/dim]",
    }

    for framework, data in payload["frameworks"].items():
        if args.framework and args.framework.lower() not in framework.lower():
            continue

        table = Table(title=framework, expand=True)
        table.add_column("Control", style="cyan", no_wrap=True)
        table.add_column("Title")
        table.add_column("Status", justify="center")
        table.add_column("Coverage", justify="right")
        table.add_column("Not detected", style="dim")

        for control in data["controls"]:
            table.add_row(
                control["control_id"],
                control["title"],
                _STATUS[control["status"]],
                f"{control['coverage']:.0%}" if control["status"] != "not_assessed" else "-",
                ", ".join(control["techniques_not_detected"]) or "-",
            )
        console.print(table)
        console.print(
            f"  Weighted coverage [bold]{data['weighted_coverage']:.0%}[/bold] "
            f"across {data['assessed_controls']} assessed controls "
            f"[dim](partial credit counted at half)[/dim]\n"
        )

    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]Compliance report[/green]  {path}")

    return 0


# --------------------------------------------------------------- stability


def _cmd_stability(args: argparse.Namespace) -> int:
    """Confidence intervals for coverage metrics across seeds."""
    from rich.table import Table

    if args.runs < 2:
        console.print("[red]--runs must be at least 2 to estimate an interval[/red]")
        return 2

    pipeline = PurpleForgePipeline(
        provider=get_provider(prefer_llm=False), seed=args.seed, noise_ratio=args.noise
    )
    console.print(f"[dim]Running {args.runs} seeds...[/dim]")

    try:
        report = pipeline.measure_stability(runs=args.runs, confidence=args.confidence)
    except (RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    console.print(
        f"\n[bold]Metric Stability[/bold]  "
        f"[dim]{report['runs']} runs, {args.confidence:.0%} bootstrap CI[/dim]\n"
    )

    table = Table(expand=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Mean", justify="right")
    table.add_column(f"{args.confidence:.0%} CI", justify="center")
    table.add_column("Min-Max", justify="center", style="dim")
    table.add_column("Stability", justify="center")

    _STABILITY = {"stable": "green", "moderate": "yellow", "volatile": "red"}
    for name, dist in report["metrics"].items():
        table.add_row(
            name,
            f"{dist['mean']:.3f}",
            f"[{dist['ci_low']:.3f}, {dist['ci_high']:.3f}]",
            f"{dist['min']:.3f}-{dist['max']:.3f}",
            f"[{_STABILITY[dist['stability']]}]{dist['stability']}[/{_STABILITY[dist['stability']]}]",
        )
    console.print(table)

    grades = report["grade_distribution"]
    console.print(
        f"\n  Modal grade [bold]{report['modal_grade']}[/bold]  "
        f"[dim]distribution: {', '.join(f'{g}x{n}' for g, n in grades.items())}[/dim]"
    )
    if len(grades) > 1:
        console.print(
            "  [yellow]The grade is not stable across seeds.[/yellow] "
            "[dim]Any single run's letter grade is partly luck.[/dim]"
        )

    flaky = report["flaky_techniques"]
    if flaky:
        console.print(
            f"\n  [yellow]Intermittently detected techniques[/yellow] "
            f"[dim](detected in some runs, missed in others)[/dim]"
        )
        for technique, rate in flaky.items():
            console.print(f"    {technique}: detected in {rate:.0%} of runs")
        console.print(
            "  [dim]These are the most actionable finding here. A technique caught\n"
            "  60% of the time is not covered; it is covered by accident.[/dim]"
        )
    else:
        console.print(
            "\n  [green]No intermittent detections[/green] "
            "[dim]every technique was either always or never caught[/dim]"
        )

    console.print(
        f"\n  [dim]Never detected: {', '.join(report['never_detected']) or 'none'}[/dim]"
    )
    return 0


# ----------------------------------------------------------- advanced views


def _run_advanced_analysis(seed: int, noise: int):
    """Run measured advanced analysis without authoring or report-only phases."""
    return PurpleForgePipeline(
        provider=get_provider(prefer_llm=False), seed=seed, noise_ratio=noise
    ).run(
        author_rules=False,
        triage_limit=0,
        test_robustness=False,
        map_compliance=False,
        advanced_analysis=True,
    )


def _write_json(payload: object, destination: str | None, label: str) -> None:
    if not destination:
        return
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]{label}[/green]  {path}")


def _cmd_attack_path(args: argparse.Namespace) -> int:
    """Explain a safe graph plan and its detection-aware alternate route."""
    from rich.table import Table

    from purpleforge.offensive import (
        AdaptivePlanner,
        AttackPlanner,
        DetectionFeedback,
        TimingDilation,
        build_reference_environment,
    )

    environment = build_reference_environment()
    if args.objective not in environment.hosts:
        console.print(f"[red]Unknown objective {args.objective!r}[/red]")
        return 2
    if args.detected_host not in environment.hosts:
        console.print(f"[red]Unknown simulated detection host {args.detected_host!r}[/red]")
        return 2

    try:
        baseline = AttackPlanner(
            environment, cost_weight=args.cost_weight, risk_weight=args.risk_weight
        ).plan(args.objective)
        if baseline is None:
            console.print(f"[yellow]Objective {args.objective} is unreachable[/yellow]")
            return 1

        feedback = DetectionFeedback(
            host=args.detected_host,
            confidence=1.0,
            severity=args.detection_severity,
            note="Simulated blue-team detection feedback",
        )
        adaptive = AdaptivePlanner(
            environment, cost_weight=args.cost_weight, risk_weight=args.risk_weight
        ).replan(
            baseline,
            [feedback],
            timing_dilation=TimingDilation(
                correlation_window_seconds=args.correlation_window,
                simulated_interval_seconds=args.simulated_interval,
            ),
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    console.print(
        "\n[bold yellow]SIMULATION ONLY[/bold yellow] [dim]- metadata graph search; "
        "no commands, sockets, authentication, exploits, or delays.[/dim]\n"
    )
    hosts = Table(title="Modelled Enterprise Terrain", expand=True)
    hosts.add_column("Host", style="cyan")
    hosts.add_column("Role")
    hosts.add_column("Defences")
    hosts.add_column("Credentials", justify="right")
    hosts.add_column("Observation multiplier", justify="right")
    for name, host in sorted(environment.hosts.items()):
        role = "entry" if host.is_internet_facing else "domain controller" if host.is_domain_controller else "internal"
        hosts.add_row(
            name,
            role,
            ", ".join(sorted(item.value for item in host.defences)) or "-",
            str(len(host.credentials)),
            f"{host.risk_multiplier:.2f}x",
        )
    console.print(hosts)

    routes = Table(title="Detection-Aware Route Comparison", expand=True)
    routes.add_column("Route")
    routes.add_column("Hosts", style="cyan")
    routes.add_column("Cost", justify="right")
    routes.add_column("Risk", justify="right")
    routes.add_column("Weighted", justify="right")
    for label, plan in (("Baseline", baseline), ("Adaptive", adaptive)):
        routes.add_row(
            label,
            " -> ".join(plan.hosts) if plan else "unreachable",
            f"{plan.operational_cost:.2f}" if plan else "-",
            f"{plan.detection_risk:.2f}" if plan else "-",
            f"{plan.weighted_score:.2f}" if plan else "-",
        )
    console.print(routes)
    console.print(
        f"[dim]Feedback penalized {args.detected_host}; route changed: "
        f"{bool(adaptive and adaptive.hosts != baseline.hosts)}[/dim]\n"
    )

    payload = {
        "simulation_only": True,
        "environment": environment.to_dict(),
        "weights": {"cost": args.cost_weight, "risk": args.risk_weight},
        "feedback": {"host": feedback.host, "severity": feedback.severity},
        "baseline": baseline.to_dict(),
        "adaptive": adaptive.to_dict() if adaptive else None,
        "route_changed": bool(adaptive and adaptive.hosts != baseline.hosts),
    }
    _write_json(payload, args.output, "Attack-path evidence")
    return 0


def _cmd_incidents(args: argparse.Namespace) -> int:
    """Show deterministic alert compression and evidence-backed incidents."""
    from rich.table import Table

    try:
        data = _run_advanced_analysis(args.seed, args.noise).incidents
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    console.print(
        f"\n[bold]Incident reconstruction[/bold]  {data['alert_count']} alerts -> "
        f"{data['incident_count']} incidents  "
        f"[cyan]({data['compression_ratio']:.2f}:1 compression)[/cyan]\n"
    )
    table = Table(title="Operational Ranking", expand=True)
    table.add_column("Incident", style="cyan")
    table.add_column("Alerts", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Confidence", justify="right")
    table.add_column("Tactic progression")
    for incident in data["incidents"][: args.limit]:
        table.add_row(
            incident["incident_id"],
            str(incident["alert_count"]),
            f"{incident['risk_score']:.1f}",
            f"{incident['confidence']:.0%}",
            " -> ".join(stage["tactic"] for stage in incident["tactic_progression"]) or "-",
        )
    console.print(table)
    console.print(
        "[dim]Ground truth is retained only under each incident's evaluation field; "
        "it never affects construction, risk, confidence, or ranking.[/dim]\n"
    )
    _write_json(data, args.output, "Incident evidence and lineage")
    return 0


def _cmd_behavioral(args: argparse.Namespace) -> int:
    """Report calibrated, holdout-evaluated behavioral analytics."""
    from rich.table import Table

    try:
        data = _run_advanced_analysis(args.seed, args.noise).behavioral
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    console.print("\n[bold]Behavioral holdout evaluation[/bold]")
    console.print(f"[dim]{data['protocol']}[/dim]\n")
    console.print(
        f"  Calibration {data['calibration_events']}  |  Evaluation {data['evaluation_events']}  |  "
        f"Precision [cyan]{data['precision']:.1%}[/cyan]  |  Recall [cyan]{data['event_recall']:.1%}[/cyan]  |  "
        f"TP / FP {data['true_positive_events']} / {data['false_positive_events']}\n"
    )
    table = Table(title="Top Anomaly Findings", expand=True)
    table.add_column("Entity", style="cyan")
    table.add_column("Feature")
    table.add_column("Score", justify="right")
    table.add_column("Method")
    table.add_column("Truth", justify="center")
    table.add_column("Technique", style="dim")
    for finding in data["top_findings"][: args.limit]:
        score = finding["score"]
        table.add_row(
            finding["entity"],
            finding["feature"],
            "infinite" if score == float("inf") else f"{score:.2f}",
            finding["method"],
            finding["ground_truth"],
            finding["technique_id"] or "-",
        )
    console.print(table)
    console.print("[dim]Imperfect precision and recall are reported rather than tuned away.[/dim]\n")
    _write_json(data, args.output, "Behavioral evaluation")
    return 0


# ---------------------------------------------------------------- validate


def _cmd_validate(args: argparse.Namespace) -> int:
    """CI gate. Non-zero exit when coverage falls below the configured floor.

    Wiring this into CI is what turns detection coverage into a tracked metric.
    A commit that deletes or breaks a rule fails the build the same way a broken
    unit test would.
    """
    pipeline = PurpleForgePipeline(
        provider=get_provider(prefer_llm=False), seed=args.seed, noise_ratio=args.noise
    )

    try:
        result = pipeline.run(
            author_rules=False,
            triage_limit=0,
            test_robustness=args.min_robustness > 0,
            map_compliance=args.min_control_coverage > 0,
        )
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    card = result.scorecard
    checks = [
        ("technique recall", card.technique_recall, args.min_recall),
        ("precision", card.precision, args.min_precision),
    ]

    if args.min_robustness > 0:
        checks.append(
            ("adversarial robustness", result.robustness["robustness_score"], args.min_robustness)
        )

    if args.min_control_coverage > 0:
        # Weakest framework governs. Averaging would let strong coverage in one
        # framework mask a failing control set in another.
        weakest = min(
            data["weighted_coverage"] for data in result.compliance["frameworks"].values()
        )
        checks.append(("control coverage (weakest framework)", weakest, args.min_control_coverage))

    console.print("[bold]Detection coverage gate[/bold]\n")
    failed = False
    for label, actual, floor in checks:
        ok = actual >= floor
        mark = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        console.print(f"  {mark}  {label}: {actual:.1%} (floor {floor:.0%})")
        failed = failed or not ok

    if result.rule_errors:
        failed = True
        console.print("\n[red]Rule errors:[/red]")
        for err in result.rule_errors:
            console.print(f"  {err['rule_id']}: {err['error']}")

    if card.gaps:
        console.print(
            f"\n[yellow]{len(card.gaps)} coverage gap(s):[/yellow] "
            + ", ".join(c.technique.technique_id for c in card.gaps)
        )

    console.print(
        f"\nGrade [bold]{card.grade}[/bold] | F1 {card.f1_score:.2f} | "
        f"{card.true_positives} TP / {card.false_positives} FP"
    )
    return 1 if failed else 0


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="purpleforge",
        description="Purple-team adversary emulation and detection validation platform.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  purpleforge run --html --navigator\n"
            "  purpleforge run --scenario PF-RANSOM-01 --noise 30\n"
            "  purpleforge run --write-rules ./review --no-ai\n"
            "  purpleforge attack-path --objective DC-01 --detected-host BUILD-01\n"
            "  purpleforge incidents --output ./out/incidents.json\n"
            "  purpleforge behavioral --output ./out/behavioral.json\n"
            "  purpleforge validate --min-recall 0.5\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"purpleforge {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run
    run = subparsers.add_parser("run", help="run the full purple-team loop")
    run.add_argument("--scenario", action="append", help="scenario id to run (repeatable)")
    run.add_argument("--scenario-dir", help="load scenarios from this directory")
    run.add_argument("--rule-dir", help="load detection rules from this directory")
    run.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducibility")
    run.add_argument("--noise", type=int, default=12, help="benign events per malicious event")
    run.add_argument("--output", default="./out", help="output directory")
    run.add_argument("--html", action="store_true", help="write an HTML report")
    run.add_argument("--json", action="store_true", help="write the raw JSON result")
    run.add_argument("--navigator", action="store_true", help="write an ATT&CK Navigator layer")
    run.add_argument("--write-rules", help="write AI rule drafts to this directory")
    run.add_argument("--no-ai", action="store_true", help="force the local heuristic engine")
    run.add_argument("--no-author", action="store_true", help="skip AI rule generation")
    run.add_argument(
        "--triage-limit",
        type=int,
        default=40,
        help="alerts given full LLM triage (rest use heuristics)",
    )
    run.add_argument(
        "--stability",
        type=int,
        default=0,
        metavar="N",
        help="re-run across N seeds for confidence intervals (0 = skip)",
    )
    run.add_argument("--no-robustness", action="store_true", help="skip the evasion harness")
    run.add_argument("--no-compliance", action="store_true", help="skip control framework mapping")
    run.add_argument(
        "--no-advanced",
        action="store_true",
        help="skip attack paths, incident reconstruction, and behavioral analytics",
    )
    run.set_defaults(func=_cmd_run)

    # robustness
    robustness = subparsers.add_parser(
        "robustness", help="test detection rules against adversarial mutation"
    )
    robustness.add_argument("--rule-dir", help="load detection rules from this directory")
    robustness.add_argument("--seed", type=int, default=1337)
    robustness.add_argument(
        "--mutation",
        action="append",
        help="limit to specific mutations (repeatable); default is all",
    )
    robustness.set_defaults(func=_cmd_robustness)

    # compliance
    compliance = subparsers.add_parser(
        "compliance", help="map detection coverage to control frameworks"
    )
    compliance.add_argument("--seed", type=int, default=1337)
    compliance.add_argument("--noise", type=int, default=12)
    compliance.add_argument(
        "--framework",
        help="limit to one framework (substring match, e.g. ISO)",
    )
    compliance.add_argument("--output", help="write the report as JSON to this path")
    compliance.set_defaults(func=_cmd_compliance)

    # stability
    stability = subparsers.add_parser(
        "stability", help="measure metric confidence intervals across seeds"
    )
    stability.add_argument("--runs", type=int, default=12, help="number of seeds to sample")
    stability.add_argument("--seed", type=int, default=1337, help="base seed")
    stability.add_argument("--noise", type=int, default=12)
    stability.add_argument(
        "--confidence", type=float, default=0.95, help="confidence level, e.g. 0.95"
    )
    stability.set_defaults(func=_cmd_stability)

    # attack-path
    attack_path = subparsers.add_parser(
        "attack-path", help="simulate baseline and detection-aware attack paths"
    )
    attack_path.add_argument("--objective", default="DC-01", help="modelled objective host")
    attack_path.add_argument(
        "--detected-host", default="BUILD-01", help="host receiving simulated detection feedback"
    )
    attack_path.add_argument("--cost-weight", type=float, default=1.0)
    attack_path.add_argument("--risk-weight", type=float, default=2.0)
    attack_path.add_argument("--detection-severity", type=float, default=20.0)
    attack_path.add_argument("--correlation-window", type=float, default=900.0)
    attack_path.add_argument("--simulated-interval", type=float, default=1200.0)
    attack_path.add_argument("--output", help="write simulation evidence as JSON")
    attack_path.set_defaults(func=_cmd_attack_path)

    # incidents
    incidents = subparsers.add_parser(
        "incidents", help="reconstruct alerts into evidence-backed incidents"
    )
    incidents.add_argument("--seed", type=int, default=1337)
    incidents.add_argument("--noise", type=int, default=12)
    incidents.add_argument("--limit", type=int, default=10, help="maximum incidents to display")
    incidents.add_argument("--output", help="write incidents and evidence lineage as JSON")
    incidents.set_defaults(func=_cmd_incidents)

    # behavioral
    behavioral = subparsers.add_parser(
        "behavioral", help="evaluate calibrated behavioral anomaly detection"
    )
    behavioral.add_argument("--seed", type=int, default=1337)
    behavioral.add_argument("--noise", type=int, default=12)
    behavioral.add_argument("--limit", type=int, default=10, help="maximum findings to display")
    behavioral.add_argument("--output", help="write behavioral evaluation as JSON")
    behavioral.set_defaults(func=_cmd_behavioral)

    # scenarios
    scenarios = subparsers.add_parser("scenarios", help="list adversary scenarios")
    scenarios.add_argument("--scenario-dir", help="load scenarios from this directory")
    scenarios.set_defaults(func=_cmd_scenarios)

    # rules
    rules = subparsers.add_parser("rules", help="list and validate detection rules")
    rules.add_argument("--rule-dir", help="load detection rules from this directory")
    rules.set_defaults(func=_cmd_rules)

    # validate
    validate = subparsers.add_parser("validate", help="CI gate on detection coverage")
    validate.add_argument("--min-recall", type=float, default=0.55, help="minimum technique recall")
    validate.add_argument("--min-precision", type=float, default=0.35, help="minimum precision")
    validate.add_argument(
        "--min-robustness",
        type=float,
        default=0.0,
        help="minimum adversarial robustness score (0 = skip the check)",
    )
    validate.add_argument(
        "--min-control-coverage",
        type=float,
        default=0.0,
        help="minimum weighted control coverage in the weakest framework (0 = skip)",
    )
    validate.add_argument("--seed", type=int, default=1337)
    validate.add_argument("--noise", type=int, default=12)
    validate.set_defaults(func=_cmd_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
