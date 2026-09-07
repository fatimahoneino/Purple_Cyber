"""Load correlation rules from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from purpleforge.detection.correlation import CorrelationRule, CorrelationStage
from purpleforge.detection.engine import RuleSyntaxError
from purpleforge.detection.loader import _techniques_from_raw
from purpleforge.models import Severity

CORRELATION_DIR = Path(__file__).parent / "correlations"


def load_correlation_rule(path: str | Path) -> CorrelationRule:
    """Load and validate one correlation rule file."""
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path.name}: expected a YAML mapping at the top level")

    correlation = raw.get("correlation")
    if not isinstance(correlation, dict):
        raise ValueError(f"{path.name}: missing 'correlation' block")

    for required in ("type", "window_seconds"):
        if required not in correlation:
            raise ValueError(f"{path.name}: correlation block is missing {required!r}")

    severity_raw = str(raw.get("level", raw.get("severity", "high"))).lower()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        raise ValueError(
            f"{path.name}: unknown severity {severity_raw!r}; "
            f"expected one of {[s.value for s in Severity]}"
        ) from None

    stages: list[CorrelationStage] = []
    for entry in correlation.get("stages", []):
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError(
                f"{path.name}: each stage must be a single-key mapping of name to selection"
            )
        name, body = next(iter(entry.items()))
        if not isinstance(body, dict):
            raise ValueError(f"{path.name}: stage {name!r} selection must be a mapping")

        # A stage may either be a bare selection, or a mapping with explicit
        # 'selection' and optional 'exclude' keys.
        if "selection" in body:
            selection = body["selection"]
            exclude = body.get("exclude")
            if not isinstance(selection, dict):
                raise ValueError(f"{path.name}: stage {name!r} selection must be a mapping")
            if exclude is not None and not isinstance(exclude, dict):
                raise ValueError(f"{path.name}: stage {name!r} exclude must be a mapping")
        else:
            selection, exclude = body, None

        stages.append(CorrelationStage(name=str(name), selection=selection, exclude=exclude))

    try:
        return CorrelationRule(
            rule_id=raw.get("id") or raw.get("rule_id") or path.stem,
            title=raw.get("title", path.stem),
            description=raw.get("description", "").strip(),
            severity=severity,
            correlation_type=str(correlation["type"]).lower(),
            window_seconds=int(correlation["window_seconds"]),
            techniques=_techniques_from_raw(raw),
            group_by=str(correlation.get("group_by", "host")),
            stages=stages,
            selection=correlation.get("selection"),
            threshold=int(correlation.get("threshold", 1)),
            distinct_field=correlation.get("distinct_field"),
            source=raw.get("source", "handwritten"),
            false_positives=raw.get("falsepositives", raw.get("false_positives", [])),
            references=raw.get("references", []),
            enabled=bool(raw.get("enabled", True)),
        )
    except RuleSyntaxError as exc:
        # Surface construction-time validation as a load error so one malformed
        # file cannot take down the whole rule set.
        raise ValueError(f"{path.name}: {exc}") from exc


def load_all_correlation_rules(directory: str | Path | None = None) -> list[CorrelationRule]:
    """Load every correlation rule in a directory. Bad files warn and are skipped."""
    directory = Path(directory) if directory else CORRELATION_DIR
    if not directory.exists():
        return []

    rules: list[CorrelationRule] = []
    seen: dict[str, str] = {}

    for path in sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml"))):
        try:
            rule = load_correlation_rule(path)
        except (ValueError, yaml.YAMLError) as exc:
            print(f"[warn] skipping correlation rule {path.name}: {exc}")
            continue
        if rule.rule_id in seen:
            print(f"[warn] duplicate correlation id {rule.rule_id} in {path.name}")
            continue
        seen[rule.rule_id] = path.name
        rules.append(rule)

    return rules
