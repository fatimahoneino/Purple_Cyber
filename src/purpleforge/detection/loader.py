"""Load Sigma-style detection rules from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from purpleforge.models import DetectionRule, Severity, TechniqueRef

RULES_DIR = Path(__file__).parent / "rules"

# Sigma writes ATT&CK references as tags: attack.t1059.001, attack.execution
_TACTIC_TAGS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}


def _techniques_from_raw(raw: dict[str, Any]) -> list[TechniqueRef]:
    """Build technique refs from either an explicit block or Sigma tags."""
    explicit = raw.get("techniques")
    if explicit:
        return [
            TechniqueRef(
                technique_id=t["technique_id"],
                name=t.get("name", t["technique_id"]),
                tactic=t.get("tactic", "unknown"),
            )
            for t in explicit
        ]

    tags = [str(t).lower().removeprefix("attack.") for t in raw.get("tags", [])]
    tactic = next((t.replace("_", "-") for t in tags if t.replace("_", "-") in _TACTIC_TAGS), "unknown")
    return [
        TechniqueRef(technique_id=tag.upper(), name=tag.upper(), tactic=tactic)
        for tag in tags
        if tag.startswith("t") and tag[1:2].isdigit()
    ]


def load_rule(path: str | Path) -> DetectionRule:
    """Load and validate one rule file."""
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path.name}: expected a YAML mapping at the top level")

    detection = raw.get("detection")
    if not isinstance(detection, dict) or not detection:
        raise ValueError(f"{path.name}: 'detection' must be a non-empty mapping")

    # Sigma keeps the condition inside the detection block; accept either place.
    selections = {k: v for k, v in detection.items() if k != "condition"}
    condition = raw.get("condition") or detection.get("condition")
    if not condition:
        raise ValueError(f"{path.name}: rule has no condition")
    if not selections:
        raise ValueError(f"{path.name}: rule defines no selections")

    severity_raw = str(raw.get("level", raw.get("severity", "medium"))).lower()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        raise ValueError(
            f"{path.name}: unknown severity {severity_raw!r}; "
            f"expected one of {[s.value for s in Severity]}"
        ) from None

    return DetectionRule(
        rule_id=raw.get("id") or raw.get("rule_id") or path.stem,
        title=raw.get("title", path.stem),
        description=raw.get("description", "").strip(),
        severity=severity,
        techniques=_techniques_from_raw(raw),
        detection=selections,
        condition=str(condition),
        source=raw.get("source", "handwritten"),
        false_positives=raw.get("falsepositives", raw.get("false_positives", [])),
        references=raw.get("references", []),
        enabled=bool(raw.get("enabled", True)),
    )


def load_all_rules(directory: str | Path | None = None) -> list[DetectionRule]:
    """Load every rule in a directory. Bad files warn and are skipped."""
    directory = Path(directory) if directory else RULES_DIR
    if not directory.exists():
        return []

    rules: list[DetectionRule] = []
    seen: dict[str, str] = {}

    for path in sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml"))):
        try:
            rule = load_rule(path)
        except (ValueError, yaml.YAMLError) as exc:
            print(f"[warn] skipping rule {path.name}: {exc}")
            continue
        if rule.rule_id in seen:
            print(f"[warn] duplicate rule id {rule.rule_id} in {path.name}; keeping {seen[rule.rule_id]}")
            continue
        seen[rule.rule_id] = path.name
        rules.append(rule)

    return rules
