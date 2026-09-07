"""AI layer: alert triage and automated detection engineering.

Two capabilities sit on top of the purple loop:

* :class:`AlertTriageAgent` -- scores and explains alerts so an analyst reads a
  ranked queue instead of a flat list.
* :class:`DetectionAuthor` -- turns the scorecard's coverage gaps into candidate
  Sigma rules.

Both run through :mod:`purpleforge.ai.provider`, which falls back to a local
heuristic engine when no API key is configured. The pipeline is fully functional
offline; an LLM improves the reasoning quality but is never required.
"""

from purpleforge.ai.provider import HeuristicProvider, LLMProvider, get_provider
from purpleforge.ai.triage import AlertTriageAgent
from purpleforge.ai.rule_author import DetectionAuthor

__all__ = [
    "AlertTriageAgent",
    "DetectionAuthor",
    "HeuristicProvider",
    "LLMProvider",
    "get_provider",
]
