"""MITRE ATT&CK Navigator layer export.

Navigator is the lingua franca for talking about coverage with security teams, so
exporting to it means the results can be dropped into an existing review instead
of asking anyone to learn a bespoke format. The JSON goes straight into
https://mitre-attack.github.io/attack-navigator/ via Open Existing Layer.
"""

from __future__ import annotations

from typing import Any

from purpleforge.scoring.scorecard import Scorecard

# Green covered, amber partial, red gap. Colour is redundant with the score and
# the comment text, so the layer stays readable for colour-blind reviewers.
_COLOURS = {
    "full": "#2e7d32",
    "partial": "#f9a825",
    "none": "#c62828",
}

_SCORES = {"full": 100, "partial": 50, "none": 0}


def build_navigator_layer(
    scorecard: Scorecard,
    name: str = "PurpleForge Detection Coverage",
    description: str | None = None,
) -> dict[str, Any]:
    """Build an ATT&CK Navigator v4.5 layer from a scorecard."""
    techniques: list[dict[str, Any]] = []

    for score in scorecard.coverage:
        status = score.status
        rules = ", ".join(score.detecting_rules) if score.detecting_rules else "no detection"
        techniques.append(
            {
                "techniqueID": score.technique.technique_id,
                "tactic": score.technique.tactic,
                "score": _SCORES[status],
                "color": _COLOURS[status],
                "comment": (
                    f"{status.upper()} | events: {score.events_generated} | "
                    f"true positives: {score.true_positives} | rules: {rules}"
                ),
                "enabled": True,
                "showSubtechniques": True,
            }
        )

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description
        or (
            f"Detection coverage measured by emulation. "
            f"Grade {scorecard.grade} | recall {scorecard.technique_recall:.0%} | "
            f"precision {scorecard.precision:.0%}"
        ),
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#c62828", "#f9a825", "#2e7d32"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Detected (full)", "color": _COLOURS["full"]},
            {"label": "Partial coverage", "color": _COLOURS["partial"]},
            {"label": "Coverage gap", "color": _COLOURS["none"]},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
    }
