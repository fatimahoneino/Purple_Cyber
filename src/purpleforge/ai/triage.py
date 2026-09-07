"""AI-assisted alert triage.

The problem being solved: the detection engine emits a flat list of alerts, and
in any realistic noise ratio most of them are false positives. An analyst working
that list top-to-bottom wastes most of their time.

The triage agent adds cross-alert context before scoring. An isolated PowerShell
alert is ambiguous; the same alert on a host that also shows credential access
and lateral movement is an active intrusion. Scoring each alert in isolation --
which is what a naive LLM-per-alert integration does -- throws that signal away,
so host correlation is computed first and fed into every verdict.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from purpleforge.ai.provider import AIProvider, HeuristicProvider, get_provider
from purpleforge.models import Alert

_RFC1918 = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)")


class AlertTriageAgent:
    """Enriches alerts with a risk score, verdict and recommended action."""

    def __init__(self, provider: AIProvider | None = None) -> None:
        self.provider = provider or get_provider()

    # ---------- context building ----------

    @staticmethod
    def _host_context(alerts: list[Alert]) -> dict[str, dict[str, Any]]:
        """Per-host alert counts and tactic spread, used to boost correlated alerts."""
        by_host: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "tactics": set(), "rules": set()}
        )
        for alert in alerts:
            entry = by_host[alert.event.host]
            entry["count"] += 1
            entry["rules"].add(alert.rule_id)
            tactic = alert.event.labels.get("tactic")
            if tactic:
                entry["tactics"].add(tactic)
        return by_host

    @staticmethod
    def _ip_scope(value: Any) -> str:
        """Classify a source address as internal, external or unknown."""
        text = str(value or "")
        if not text:
            return "unknown"
        return "internal" if _RFC1918.match(text) else "external"

    @classmethod
    def _alert_context(cls, alert: Alert, host_entry: dict[str, Any]) -> dict[str, Any]:
        flat = alert.event.flatten()
        return {
            "rule_title": alert.rule_title,
            "severity": alert.severity.value,
            "techniques": alert.techniques,
            "tactic": alert.event.labels.get("tactic", ""),
            "host": alert.event.host,
            "user": alert.event.user,
            "event_type": alert.event.event_type,
            "source": alert.event.source,
            "process_name": flat.get("process.name", ""),
            "command_line": flat.get("process.command_line", ""),
            "parent_name": flat.get("process.parent_name", ""),
            "integrity_level": flat.get("process.integrity_level", ""),
            "destination_ip": flat.get("destination.ip", ""),
            "destination_domain": flat.get("destination.domain", ""),
            "source_ip": flat.get("source.ip", ""),
            "source_ip_scope": cls._ip_scope(flat.get("source.ip")),
            # Correlation counts exclude the alert itself.
            "correlated_alert_count": max(host_entry["count"] - 1, 0),
            "distinct_tactics_on_host": len(host_entry["tactics"]),
        }

    # ---------- public API ----------

    def triage(self, alerts: list[Alert], limit: int | None = None) -> list[Alert]:
        """Attach a triage verdict to each alert, in place, and return them ranked.

        Args:
            alerts: Alerts to enrich.
            limit: When set, only the ``limit`` highest-severity alerts get the
                full treatment. Relevant for the LLM provider, where every alert
                is a network round trip; the rest still get heuristic scores.
        """
        if not alerts:
            return []

        host_context = self._host_context(alerts)
        heuristic = HeuristicProvider()

        # Severity order decides who gets the expensive provider when limited.
        ordered = sorted(alerts, key=lambda a: -a.severity.rank)
        budget = len(ordered) if limit is None else max(0, limit)

        for index, alert in enumerate(ordered):
            context = self._alert_context(alert, host_context[alert.event.host])
            engine = self.provider if index < budget else heuristic
            scorer = getattr(engine, "score_alert", heuristic.score_alert)
            verdict = scorer(context)
            verdict["ground_truth"] = (
                "true_positive" if alert.is_true_positive else "false_positive"
            )
            alert.triage = verdict

        return self.rank(alerts)

    @staticmethod
    def rank(alerts: list[Alert]) -> list[Alert]:
        """Sort by risk score, then severity, then time."""
        return sorted(
            alerts,
            key=lambda a: (
                -(a.triage or {}).get("risk_score", 0),
                -a.severity.rank,
                a.event.timestamp,
            ),
        )

    @staticmethod
    def summarise(alerts: list[Alert]) -> dict[str, Any]:
        """Aggregate triage stats, including how well the scoring separated signal.

        ``separation`` is the gap between mean score on real detections and mean
        score on false positives. It is the honest measure of whether triage is
        adding value: a small gap means the scores are not helping an analyst
        prioritise, regardless of how confident the verdicts look.
        """
        triaged = [a for a in alerts if a.triage]
        if not triaged:
            return {"triaged": 0}

        buckets: dict[str, int] = defaultdict(int)
        tp_scores: list[int] = []
        fp_scores: list[int] = []

        for alert in triaged:
            buckets[alert.triage.get("verdict", "unknown")] += 1
            score = alert.triage.get("risk_score", 0)
            (tp_scores if alert.is_true_positive else fp_scores).append(score)

        mean_tp = sum(tp_scores) / len(tp_scores) if tp_scores else 0.0
        mean_fp = sum(fp_scores) / len(fp_scores) if fp_scores else 0.0

        # Of everything triage pushed to the top, how much was real?
        escalated = [a for a in triaged if (a.triage or {}).get("risk_score", 0) >= 80]
        escalated_tp = sum(1 for a in escalated if a.is_true_positive)

        return {
            "triaged": len(triaged),
            "verdicts": dict(buckets),
            "mean_score_true_positive": round(mean_tp, 1),
            "mean_score_false_positive": round(mean_fp, 1),
            "separation": round(mean_tp - mean_fp, 1),
            "escalated_count": len(escalated),
            "escalated_precision": round(escalated_tp / len(escalated), 3) if escalated else 0.0,
            "provider": (triaged[0].triage or {}).get("provider", "unknown"),
        }
