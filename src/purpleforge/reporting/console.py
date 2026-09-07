"""Rich terminal report.

Written so the headline numbers land in the first screen: grade, recall,
precision, then the gap list, then the AI contribution with its holdout check.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from purpleforge.pipeline import PipelineResult


def _supports_unicode() -> bool:
    """Whether stdout can encode the block-drawing characters.

    On Windows, piping output to a file switches stdout to cp1252, which cannot
    encode the bar glyphs and raises UnicodeEncodeError mid-report. Checking the
    encoding up front keeps `purpleforge run > report.txt` working.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "█░→".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True

_GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "bold red"}
_STATUS_STYLE = {"full": "green", "partial": "yellow", "none": "red"}
_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _metric(label: str, value: str, style: str = "white") -> Text:
    text = Text()
    text.append(f"{label}: ", style="dim")
    text.append(value, style=style)
    return text


def render_console(result: PipelineResult, console: Console | None = None) -> None:
    """Print the full assessment to the terminal."""
    console = console or Console()
    card = result.scorecard

    # ---- headline ----
    grade_style = _GRADE_STYLE.get(card.grade, "white")
    header = Text()
    header.append("PurpleForge Detection Assessment\n", style="bold magenta")
    header.append(f"run {result.run_id}  |  AI provider: {result.provider_name}", style="dim")
    console.print(Panel(header, border_style="magenta"))

    summary = Table.grid(padding=(0, 3))
    summary.add_row(
        _metric("Grade", card.grade, grade_style),
        _metric("F1", f"{card.f1_score:.2f}"),
        _metric("Technique recall", f"{card.technique_recall:.0%}"),
        _metric("Precision", f"{card.precision:.0%}"),
    )
    summary.add_row(
        _metric("Techniques", f"{card.techniques_detected}/{card.techniques_total}"),
        _metric("Events", str(card.total_events)),
        _metric("Alerts", str(card.total_alerts)),
        _metric("TP / FP", f"{card.true_positives} / {card.false_positives}", "cyan"),
    )
    summary.add_row(
        _metric("Alerts per real finding", f"{card.alert_volume_per_true_positive:.1f}"),
        _metric("Event recall", f"{card.event_recall:.0%}"),
        _metric("Scenarios", str(len(card.scenario_results))),
        _metric("Gaps", str(len(card.gaps)), "red" if card.gaps else "green"),
    )
    console.print(summary)
    console.print()

    # ---- coverage by tactic ----
    tactic_table = Table(title="Coverage by ATT&CK Tactic", title_style="bold", expand=True)
    tactic_table.add_column("Tactic", style="cyan")
    tactic_table.add_column("Detected", justify="right")
    tactic_table.add_column("Coverage", justify="right")
    tactic_table.add_column("Bar")

    full_char, empty_char = ("█", "░") if _supports_unicode() else ("#", ".")
    for tactic, data in card.by_tactic().items():
        pct = data["coverage"]
        filled = int(pct * 20)
        bar = Text(full_char * filled + empty_char * (20 - filled))
        bar.stylize("green" if pct >= 0.8 else "yellow" if pct >= 0.4 else "red")
        tactic_table.add_row(
            tactic,
            f"{data['detected']}/{data['total']}",
            f"{pct:.0%}",
            bar,
        )
    console.print(tactic_table)
    console.print()

    # ---- technique detail ----
    coverage_table = Table(title="Technique Detail", title_style="bold", expand=True)
    coverage_table.add_column("Technique", style="cyan", no_wrap=True)
    coverage_table.add_column("Name")
    coverage_table.add_column("Status", justify="center")
    coverage_table.add_column("Events", justify="right")
    coverage_table.add_column("TP", justify="right")
    coverage_table.add_column("Detecting rules", style="dim")

    for score in card.coverage:
        coverage_table.add_row(
            score.technique.technique_id,
            score.technique.name,
            Text(score.status, style=_STATUS_STYLE[score.status]),
            str(score.events_generated),
            str(score.true_positives),
            ", ".join(score.detecting_rules) or "-",
        )
    console.print(coverage_table)
    console.print()

    # ---- noisiest rules ----
    noisy = card.noisiest_rules()
    if noisy:
        noise_table = Table(
            title="Tuning Backlog: Rules Generating False Positives",
            title_style="bold",
            expand=True,
        )
        noise_table.add_column("Rule", style="cyan")
        noise_table.add_column("Title")
        noise_table.add_column("FP", justify="right", style="red")
        noise_table.add_column("TP", justify="right", style="green")
        noise_table.add_column("FP rate", justify="right")
        for entry in noisy:
            noise_table.add_row(
                entry["rule_id"],
                entry["title"],
                str(entry["fp"]),
                str(entry["tp"]),
                f"{entry['fp_rate']:.0%}",
            )
        console.print(noise_table)
        console.print()

    # ---- AI triage ----
    triage = result.triage_summary
    if triage.get("triaged"):
        panel = Table.grid(padding=(0, 3))
        panel.add_row(
            _metric("Alerts triaged", str(triage["triaged"])),
            _metric("Escalated", str(triage["escalated_count"])),
            _metric("Escalation precision", f"{triage['escalated_precision']:.0%}", "cyan"),
        )
        panel.add_row(
            _metric("Mean score (real)", str(triage["mean_score_true_positive"]), "green"),
            _metric("Mean score (noise)", str(triage["mean_score_false_positive"]), "red"),
            _metric("Separation", str(triage["separation"]), "bold cyan"),
        )
        console.print(
            Panel(panel, title="AI Alert Triage", border_style="blue", title_align="left")
        )
        console.print()

    # ---- top alerts ----
    if result.alerts:
        alert_table = Table(
            title="Highest-Risk Alerts (AI ranked)", title_style="bold", expand=True
        )
        alert_table.add_column("Risk", justify="right")
        alert_table.add_column("Severity", justify="center")
        alert_table.add_column("Rule")
        alert_table.add_column("Host", style="cyan")
        alert_table.add_column("Truth", justify="center")
        alert_table.add_column("Top reason", style="dim")

        for alert in result.alerts[:10]:
            triage_data = alert.triage or {}
            reasons = triage_data.get("reasoning", [])
            truth = "TP" if alert.is_true_positive else "FP"
            alert_table.add_row(
                str(triage_data.get("risk_score", "-")),
                Text(alert.severity.value, style=_SEVERITY_STYLE[alert.severity.value]),
                alert.rule_title[:44],
                alert.event.host,
                Text(truth, style="green" if truth == "TP" else "red"),
                reasons[-1] if reasons else "-",
            )
        console.print(alert_table)
        console.print()

    # ---- AI detection engineering ----
    if result.proposed_rules:
        prop_table = Table(
            title="AI-Drafted Detections (disabled, pending review)",
            title_style="bold",
            expand=True,
        )
        prop_table.add_column("Rule", style="cyan")
        prop_table.add_column("Technique")
        prop_table.add_column("Severity", justify="center")
        prop_table.add_column("Condition", style="dim")
        for rule in result.proposed_rules:
            prop_table.add_row(
                rule.rule_id,
                ", ".join(sorted(rule.technique_ids)),
                Text(rule.severity.value, style=_SEVERITY_STYLE[rule.severity.value]),
                rule.condition[:46],
            )
        console.print(prop_table)
        console.print()

    if result.rejected_proposals:
        console.print("[bold]Rejected drafts[/bold] (failed validation)")
        for item in result.rejected_proposals:
            console.print(f"  [red]x[/red] {item['technique_id']}: {item['reason']}")
        console.print()

    # ---- improvement with holdout ----
    imp = result.improvement
    if imp:
        table = Table(title="Effect of AI-Drafted Rules", title_style="bold", expand=True)
        table.add_column("Evaluation")
        table.add_column("Recall", justify="right")
        table.add_column("Precision", justify="right")
        table.add_column("F1", justify="right")
        table.add_column("Grade", justify="center")

        def add(label: str, metrics: dict, style: str = "") -> None:
            table.add_row(
                Text(label, style=style),
                f"{metrics['technique_recall']:.0%}",
                f"{metrics['precision']:.0%}",
                f"{metrics['f1_score']:.2f}",
                Text(metrics["grade"], style=_GRADE_STYLE.get(metrics["grade"], "")),
            )

        add("Baseline rules", imp["baseline"])
        add("+ AI rules (in-sample)", imp["with_ai_rules"], "yellow")
        holdout = imp.get("holdout", {})
        if holdout:
            add("+ AI rules (holdout)", holdout["with_ai_rules"], "bold green")
        console.print(table)

        if holdout:
            recovered = holdout["delta"]["techniques_recovered"]
            overfit = holdout["overfit_count"]
            console.print(
                f"\n  Holdout re-emits every scenario under seed {holdout['seed']} with fresh "
                "noise and new attacker infrastructure."
            )
            console.print(
                f"  [green]{recovered} technique(s) recovered and generalised[/green]"
                + (
                    f"  |  [red]{overfit} overfit to the training telemetry: "
                    f"{', '.join(holdout['in_sample_only'])}[/red]"
                    if overfit
                    else "  |  [green]no overfitting detected[/green]"
                )
            )
            if imp.get("remaining_gaps"):
                console.print(
                    f"  [yellow]Remaining gaps: {', '.join(imp['remaining_gaps'])}[/yellow]"
                )
        console.print()

    # ---- correlation ----
    correlated = result.correlation_alerts
    if correlated:
        table = Table(
            title="Correlation Alerts (multi-event patterns)", title_style="bold", expand=True
        )
        table.add_column("Rule", style="cyan")
        table.add_column("Pattern", style="dim")
        table.add_column("Events", justify="right")
        table.add_column("Purity", justify="right")
        table.add_column("Truth", justify="center")
        for alert in correlated[:8]:
            truth = "TP" if alert.is_true_positive else "FP"
            purity = alert.correlation_purity
            table.add_row(
                alert.rule_id,
                (alert.correlation_type or "")[:38],
                str(len(alert.all_events)),
                Text(
                    f"{purity:.0%}",
                    style="green" if purity == 1.0 else "yellow" if purity >= 0.5 else "red",
                ),
                Text(truth, style="green" if truth == "TP" else "red"),
            )
        console.print(table)
        console.print(
            "[dim]  Purity is the share of correlated events that were real attack "
            "activity.\n  A low-purity chain is technically a hit but still leaves the "
            "analyst sifting.[/dim]\n"
        )

    # ---- advanced offensive + defensive analysis ----
    attack_paths = result.attack_paths
    baseline = attack_paths.get("baseline") if attack_paths else None
    if baseline:
        adaptive = attack_paths.get("adaptive")
        table = Table(title="Offensive Route Simulation", title_style="bold", expand=True)
        table.add_column("Route")
        table.add_column("Hosts", style="cyan")
        table.add_column("Cost", justify="right")
        table.add_column("Detection risk", justify="right")
        table.add_column("Weighted score", justify="right")

        def add_route(label: str, route: dict[str, object] | None) -> None:
            if not route:
                table.add_row(label, "unavailable", "-", "-", "-")
                return
            hosts = route.get("hosts", [])
            table.add_row(
                label,
                " -> ".join(str(host) for host in hosts) or "-",
                f"{float(route.get('operational_cost', 0)):.2f}",
                f"{float(route.get('detection_risk', 0)):.2f}",
                f"{float(route.get('weighted_score', 0)):.2f}",
            )

        add_route("Baseline", baseline)
        add_route("Adaptive", adaptive)
        console.print(table)
        feedback = attack_paths.get("feedback", {})
        if feedback:
            console.print(
                Text(
                    "  Feedback: "
                    f"{feedback.get('host', '-')} | confidence "
                    f"{float(feedback.get('confidence', 0)):.0%} | severity "
                    f"{feedback.get('severity', '-')} | {feedback.get('note', '-')}",
                    style="dim",
                )
            )
        console.print(
            Text(
                "  SIMULATION ONLY - "
                + str(
                    attack_paths.get(
                        "safety",
                        "Metadata-only planning; no commands, authentication, sockets, or attack execution.",
                    )
                ),
                style="bold yellow",
            )
        )
        console.print()

    incident_data = result.incidents
    if incident_data and "alert_count" in incident_data:
        alert_count = int(incident_data.get("alert_count", 0))
        incident_count = int(incident_data.get("incident_count", 0))
        compression = float(incident_data.get("compression_ratio", 0))
        incident_grid = Table.grid(padding=(0, 3))
        incident_grid.add_row(
            _metric("Alerts", str(alert_count)),
            _metric("Incidents", str(incident_count)),
            _metric("Compression", f"{compression:.2f}:1", "cyan"),
        )
        console.print(
            Panel(
                incident_grid,
                title="Defensive Incident Reconstruction",
                border_style="blue",
                title_align="left",
            )
        )
        top_incidents = incident_data.get("incidents", [])[:8]
        if top_incidents:
            table = Table(title="Top Incidents (operational ranking)", expand=True)
            table.add_column("Incident", style="cyan")
            table.add_column("Alerts", justify="right")
            table.add_column("Risk", justify="right")
            table.add_column("Confidence", justify="right")
            table.add_column("Tactic progression")
            for incident in top_incidents:
                progression = " -> ".join(
                    str(stage.get("tactic", "-"))
                    for stage in incident.get("tactic_progression", [])
                ) or "-"
                table.add_row(
                    str(incident.get("incident_id", "-")),
                    str(incident.get("alert_count", 0)),
                    f"{float(incident.get('risk_score', 0)):.1f}",
                    f"{float(incident.get('confidence', 0)):.0%}",
                    progression,
                )
            console.print(table)

            purity = Table(title="Evaluation Purity (ground truth only)", expand=True)
            purity.add_column("Incident", style="cyan")
            purity.add_column("Alert purity", justify="right")
            purity.add_column("Event purity", justify="right")
            for incident in top_incidents:
                evaluation = incident.get("evaluation", {})
                purity.add_row(
                    str(incident.get("incident_id", "-")),
                    f"{float(evaluation.get('alert_purity', 0)):.0%}",
                    f"{float(evaluation.get('event_purity', 0)):.0%}",
                )
            console.print(purity)
            console.print(
                "[dim]  Purity uses ground truth for evaluation only; it does not build or rank incidents.[/dim]"
            )
        console.print()

    behavioral = result.behavioral
    if behavioral and "protocol" in behavioral:
        grid = Table.grid(padding=(0, 3))
        grid.add_row(
            _metric("Calibration", str(behavioral.get("calibration_events", 0))),
            _metric("Evaluation", str(behavioral.get("evaluation_events", 0))),
            _metric("Precision", f"{float(behavioral.get('precision', 0)):.0%}", "cyan"),
            _metric("Recall", f"{float(behavioral.get('event_recall', 0)):.0%}", "cyan"),
            _metric(
                "TP / FP",
                f"{behavioral.get('true_positive_events', 0)} / "
                f"{behavioral.get('false_positive_events', 0)}",
            ),
        )
        console.print(
            Panel(grid, title="Behavioral Analytics", border_style="magenta", title_align="left")
        )
        console.print(Text("  Protocol: " + str(behavioral["protocol"]), style="dim"))
        findings = behavioral.get("top_findings", [])[:10]
        if findings:
            table = Table(title="Top Behavioral Findings", expand=True)
            table.add_column("Entity", style="cyan")
            table.add_column("Feature")
            table.add_column("Score", justify="right")
            table.add_column("Samples", justify="right")
            table.add_column("Truth", justify="center")
            table.add_column("Technique", style="dim")
            for finding in findings:
                truth = str(finding.get("ground_truth", "-"))
                score = float(finding.get("score", 0))
                table.add_row(
                    str(finding.get("entity", "-")),
                    str(finding.get("feature", "-")),
                    "infinite" if score == float("inf") else f"{score:.2f}",
                    str(finding.get("sample_count", 0)),
                    Text(truth, style="green" if truth == "attack" else "red"),
                    str(finding.get("technique_id") or "-"),
                )
            console.print(table)
        console.print()

    # ---- robustness ----
    robustness = result.robustness
    if robustness.get("cases_tested"):
        score = robustness["robustness_score"]
        style = "green" if score >= 0.9 else "yellow" if score >= 0.75 else "red"
        grid = Table.grid(padding=(0, 3))
        grid.add_row(
            _metric("Robustness", f"{score:.0%}", style),
            _metric("Cases tested", str(robustness["cases_tested"])),
            _metric("Evasions", str(robustness["evasions_found"]), "red"),
            _metric("Fragile rules", str(len(robustness["fragile_rules"])), "red"),
        )
        console.print(
            Panel(
                grid,
                title="Adversarial Robustness",
                border_style="yellow",
                title_align="left",
            )
        )
        if robustness["fragile_rules"]:
            for rule_id, mutations in robustness["fragile_rules"].items():
                survival = robustness["rule_robustness"].get(rule_id, 0.0)
                console.print(
                    f"  [red]x[/red] {rule_id} [dim]({survival:.0%} survival)[/dim] "
                    f"defeated by {', '.join(mutations)}"
                )
        console.print(
            "[dim]  Mutations preserve what the command does, so a rule that stops "
            "firing was\n  matching the spelling of the technique rather than the "
            "behaviour.[/dim]\n"
        )

    # ---- stability ----
    stability = result.stability
    if stability.get("metrics"):
        table = Table(
            title=f"Metric Stability ({stability['runs']} seeds)",
            title_style="bold",
            expand=True,
        )
        table.add_column("Metric", style="cyan")
        table.add_column("Mean", justify="right")
        table.add_column("95% CI", justify="center")
        table.add_column("Min-Max", justify="center", style="dim")
        table.add_column("Stability", justify="center")

        styles = {"stable": "green", "moderate": "yellow", "volatile": "red"}
        for name, dist in stability["metrics"].items():
            table.add_row(
                name.replace("_", " "),
                f"{dist['mean']:.3f}",
                f"[{dist['ci_low']:.3f}, {dist['ci_high']:.3f}]",
                f"{dist['min']:.3f}-{dist['max']:.3f}",
                Text(dist["stability"], style=styles[dist["stability"]]),
            )
        console.print(table)

        grades = stability["grade_distribution"]
        console.print(
            f"  Modal grade [bold]{stability['modal_grade']}[/bold] "
            f"[dim]({', '.join(f'{g}x{n}' for g, n in grades.items())})[/dim]"
        )
        if len(grades) > 1:
            console.print(
                "  [yellow]Grade is not stable across seeds; the interval is the "
                "citable result, not the letter.[/yellow]"
            )
        if stability["flaky_techniques"]:
            console.print("  [yellow]Intermittently detected:[/yellow]")
            for technique, rate in stability["flaky_techniques"].items():
                console.print(f"    {technique}: {rate:.0%} of runs")
        console.print()

    # ---- compliance ----
    compliance = result.compliance
    if compliance.get("frameworks"):
        table = Table(title="Control Effectiveness", title_style="bold", expand=True)
        table.add_column("Framework", style="cyan")
        table.add_column("Weighted", justify="right")
        table.add_column("Effective", justify="right", style="green")
        table.add_column("Partial", justify="right", style="yellow")
        table.add_column("Ineffective", justify="right", style="red")
        for framework, data in compliance["frameworks"].items():
            pct = data["weighted_coverage"]
            table.add_row(
                framework,
                Text(
                    f"{pct:.0%}",
                    style="green" if pct >= 0.8 else "yellow" if pct >= 0.5 else "red",
                ),
                str(data["effective"]),
                str(data["partially_effective"]),
                str(data["ineffective"]),
            )
        console.print(table)
        console.print(
            "[dim]  Control status is derived from detection outcomes, not asserted. "
            "Run\n  'purpleforge compliance' for the control-by-control breakdown.[/dim]\n"
        )

    if result.rule_errors:
        console.print("[bold red]Rule errors[/bold red]")
        for err in result.rule_errors:
            console.print(f"  {err['rule_id']}: {err['error']}")
