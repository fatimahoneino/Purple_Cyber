"""Automated detection engineering.

This closes the purple loop. Scoring identifies techniques red executed and blue
missed; this module drafts analytics for those gaps, then immediately re-tests
them against the same telemetry so a proposal arrives with evidence attached.

Two guardrails matter, because a generator that is not constrained will happily
produce rules that look impressive and are worthless:

1. **Overly broad rules are rejected.** A candidate that fires on benign noise is
   discarded, not shipped with a warning. A rule matching everything achieves
   perfect recall and is worse than no rule.
2. **Nothing is auto-enabled.** Proposals are written to a review directory as
   ``enabled: false`` drafts. Automated detection engineering assists a human
   reviewer; it does not replace one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from purpleforge.ai.provider import AIProvider, get_provider
from purpleforge.detection.engine import DetectionEngine, RuleSyntaxError
from purpleforge.models import DetectionRule, Event, Severity, TechniqueRef
from purpleforge.scoring.scorecard import CoverageScore

# Field-level templates keyed by ATT&CK technique. These encode the analytic
# approach a detection engineer would reach for, so even the offline path
# proposes something defensible rather than a generic string match.
_TECHNIQUE_STRATEGY: dict[str, dict[str, Any]] = {
    "T1566.001": {
        "severity": "medium",
        "hint": "attachment file type combined with a weak sender authentication result",
        "fields": ["email.attachment_name", "email.spf_result", "email.sender"],
    },
    "T1134.001": {
        "severity": "high",
        "hint": "process access to a privileged token holder with an unbacked call trace",
        "fields": ["process.target_name", "process.granted_access", "process.call_trace"],
    },
    "T1041": {
        "severity": "high",
        "hint": "large outbound transfer to a low-reputation destination",
        "fields": ["network.bytes_out", "destination.domain", "destination.port"],
    },
    "T1046": {
        "severity": "medium",
        "hint": "one source touching many destinations on a single port in a short window",
        "fields": ["network.unique_destinations", "destination.port"],
    },
    "T1213.003": {
        "severity": "medium",
        "hint": "repository clone volume far above the user's baseline, outside work hours",
        "fields": ["git.repos_cloned", "git.baseline_repos_per_day", "time.hour_local"],
    },
    "T1213": {
        "severity": "medium",
        "hint": "query returning orders of magnitude more rows than the user's baseline",
        "fields": ["db.rows_returned", "db.baseline_rows_per_query"],
    },
    "T1560.001": {
        "severity": "low",
        "hint": "archive utility invoked with encryption and header-hiding flags",
        "fields": ["process.name", "process.command_line"],
    },
    "T1567.002": {
        "severity": "high",
        "hint": "bulk upload to personal cloud storage",
        "fields": ["destination.domain", "network.bytes_out", "auth.account_type"],
    },
    "T1052.001": {
        "severity": "medium",
        "hint": "large write to newly seen removable media",
        "fields": ["device.serial", "file.size", "device.first_seen"],
    },
}

_NUMERIC_THRESHOLD_RATIO = 0.6  # propose a threshold below the observed value


class DetectionAuthor:
    """Drafts, validates and persists candidate detection rules for coverage gaps."""

    def __init__(self, provider: AIProvider | None = None) -> None:
        self.provider = provider or get_provider()
        self.rejected: list[dict[str, Any]] = []

    # ------------------------------------------------------------- generation

    def propose(
        self,
        gap: CoverageScore,
        events: list[Event],
        existing_rules: list[DetectionRule] | None = None,
    ) -> DetectionRule | None:
        """Draft one rule for a missed technique, or ``None`` if it cannot be validated."""
        technique = gap.technique
        samples = [e for e in events if e.technique_id == technique.technique_id]
        if not samples:
            self._reject(technique.technique_id, "no sample telemetry for this technique")
            return None

        candidate = self._draft(technique, samples)
        if candidate is None:
            return None

        verdict = self._validate(candidate, samples, events, existing_rules or [])
        if not verdict["accepted"]:
            self._reject(technique.technique_id, verdict["reason"])
            return None

        return candidate

    def propose_all(
        self,
        gaps: list[CoverageScore],
        events: list[Event],
        existing_rules: list[DetectionRule] | None = None,
    ) -> list[DetectionRule]:
        """Draft rules for every gap. Accepted proposals accumulate as context."""
        accepted: list[DetectionRule] = []
        known = list(existing_rules or [])

        for gap in gaps:
            rule = self.propose(gap, events, known + accepted)
            if rule is not None:
                accepted.append(rule)
        return accepted

    # ---------------------------------------------------------------- drafting

    def _draft(self, technique: TechniqueRef, samples: list[Event]) -> DetectionRule | None:
        """Build a candidate, asking the LLM first and falling back to templates."""
        strategy = _TECHNIQUE_STRATEGY.get(
            technique.technique_id,
            _TECHNIQUE_STRATEGY.get(technique.base_technique, {}),
        )
        flat = samples[0].flatten()
        template = self._template_detection(strategy, flat)

        if not self.provider.is_llm:
            return self._assemble(technique, strategy, template)

        system = (
            "You are a detection engineer writing Sigma rules. Respond with one JSON "
            "object only. Keys: 'detection' (mapping of selection names to field "
            "mappings), 'condition' (boolean expression over those selection names), "
            "'title', 'description', 'level' (one of low/medium/high/critical), "
            "'falsepositives' (array of strings). "
            "Supported field modifiers: |contains |startswith |endswith |re |gt |gte "
            "|lt |lte |in |exists. Prefer behavioural fields and numeric thresholds "
            "over brittle literal strings. Never match on a field that is absent from "
            "the sample telemetry."
        )
        user = json.dumps(
            {
                "technique": {
                    "id": technique.technique_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                },
                "analytic_hint": strategy.get("hint", ""),
                "available_fields": sorted(flat.keys()),
                "sample_events": [e.flatten() for e in samples[:3]],
            },
            indent=2,
            default=str,
        )

        payload = self.provider.complete_json(system, user, fallback={})
        detection = payload.get("detection")
        condition = payload.get("condition")

        if not isinstance(detection, dict) or not detection or not isinstance(condition, str):
            return self._assemble(technique, strategy, template)

        return self._assemble(
            technique,
            strategy,
            {"detection": detection, "condition": condition},
            title=payload.get("title"),
            description=payload.get("description"),
            level=payload.get("level"),
            false_positives=payload.get("falsepositives"),
        )

    def _template_detection(
        self, strategy: dict[str, Any], flat: dict[str, Any]
    ) -> dict[str, Any]:
        """Build detection logic from observed sample values.

        Numeric fields become thresholds below the observed value so the rule
        generalises; string fields become substring matches on a distinctive token.
        """
        candidate_fields = [f for f in strategy.get("fields", []) if f in flat]
        if not candidate_fields:
            # Fall back to whatever discriminating fields the event does carry.
            candidate_fields = [
                f
                for f in ("process.name", "process.command_line", "event_type", "destination.domain")
                if f in flat
            ][:2]

        selection: dict[str, Any] = {"event_type": flat.get("event_type")}

        for field_name in candidate_fields:
            value = flat[field_name]
            if isinstance(value, bool):
                selection[field_name] = value
            elif isinstance(value, (int, float)):
                threshold = int(value * _NUMERIC_THRESHOLD_RATIO) or 1
                selection[f"{field_name}|gte"] = threshold
            else:
                token = self._distinctive_token(str(value))
                if token:
                    selection[f"{field_name}|contains"] = token

        return {"detection": {"selection": selection}, "condition": "selection"}

    @staticmethod
    def _distinctive_token(value: str) -> str | None:
        """Pick the most specific-looking token from a string value.

        Longest token wins as a rough proxy for specificity: paths, flags and tool
        names outlast filler words, and short generic fragments are what make a
        generated rule fire on everything.
        """
        parts = [p.strip("\"'()[]{},;") for p in value.replace("\\", " ").split()]
        parts = [p for p in parts if len(p) >= 5]
        if not parts:
            return value if len(value) >= 4 else None
        return max(parts, key=len)

    def _assemble(
        self,
        technique: TechniqueRef,
        strategy: dict[str, Any],
        logic: dict[str, Any],
        title: str | None = None,
        description: str | None = None,
        level: str | None = None,
        false_positives: list[str] | None = None,
    ) -> DetectionRule:
        severity_raw = str(level or strategy.get("severity", "medium")).lower()
        try:
            severity = Severity(severity_raw)
        except ValueError:
            severity = Severity.MEDIUM

        rule_id = f"PF-AI-{technique.technique_id.replace('.', '-')}"
        return DetectionRule(
            rule_id=rule_id,
            title=title or f"[AI draft] {technique.name} ({technique.technique_id})",
            description=(
                description
                or f"Auto-generated candidate analytic for {technique.technique_id} "
                f"({technique.name}). Approach: {strategy.get('hint', 'match observed behaviour')}. "
                "Generated from emulated telemetry and pending analyst review."
            ),
            severity=severity,
            techniques=[technique],
            detection=logic["detection"],
            condition=logic["condition"],
            source=f"ai:{self.provider.name}",
            false_positives=false_positives
            or ["Unreviewed AI draft: validate against production telemetry before enabling"],
            references=[technique.url],
            enabled=False,  # never auto-enable a generated rule
        )

    # -------------------------------------------------------------- validation

    def _validate(
        self,
        candidate: DetectionRule,
        samples: list[Event],
        all_events: list[Event],
        existing: list[DetectionRule],
    ) -> dict[str, Any]:
        """Test a candidate for syntax, true positives, noise and duplication."""
        engine = DetectionEngine([candidate])

        try:
            hits = sum(1 for e in samples if engine.matches(candidate, e))
        except RuleSyntaxError as exc:
            return {"accepted": False, "reason": f"invalid rule syntax: {exc}"}

        if hits == 0:
            return {
                "accepted": False,
                "reason": "rule does not match the telemetry it was generated from",
            }

        benign = [e for e in all_events if not e.is_malicious]
        try:
            fp = sum(1 for e in benign if engine.matches(candidate, e))
        except RuleSyntaxError as exc:
            return {"accepted": False, "reason": f"invalid rule syntax on benign events: {exc}"}

        if benign and fp / len(benign) > 0.01:
            return {
                "accepted": False,
                "reason": f"too broad: matched {fp}/{len(benign)} benign events",
            }

        # Wrong-technique matches mean the logic is not specific to this behaviour.
        other_malicious = [
            e
            for e in all_events
            if e.is_malicious and e.technique_id != candidate.techniques[0].technique_id
        ]
        cross = sum(1 for e in other_malicious if engine.matches(candidate, e))
        if other_malicious and cross / len(other_malicious) > 0.25:
            return {
                "accepted": False,
                "reason": f"not specific: also matched {cross} events from other techniques",
            }

        if any(r.fingerprint == candidate.fingerprint for r in existing):
            return {"accepted": False, "reason": "duplicate of an existing rule"}

        return {"accepted": True, "reason": "validated", "true_positives": hits, "false_positives": fp}

    def _reject(self, technique_id: str, reason: str) -> None:
        self.rejected.append({"technique_id": technique_id, "reason": reason})

    # ------------------------------------------------------------ persistence

    @staticmethod
    def write(rules: list[DetectionRule], directory: str | Path) -> list[Path]:
        """Write drafts to a review directory as disabled Sigma-style YAML."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []

        for rule in rules:
            payload = {
                "id": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "level": rule.severity.value,
                "source": rule.source,
                "enabled": False,
                "tags": [f"attack.{rule.techniques[0].tactic}"]
                + [f"attack.{t.technique_id.lower()}" for t in rule.techniques],
                "references": rule.references,
                "detection": rule.detection,
                "condition": rule.condition,
                "falsepositives": rule.false_positives,
            }
            path = directory / f"{rule.rule_id.lower()}.yml"
            path.write_text(
                "# Generated by PurpleForge. Review before enabling.\n"
                + yaml.safe_dump(payload, sort_keys=False, width=100),
                encoding="utf-8",
            )
            written.append(path)

        return written
