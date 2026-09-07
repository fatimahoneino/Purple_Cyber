"""Pluggable AI backends.

The provider abstraction exists so the platform degrades gracefully. A portfolio
project that only runs when the reviewer holds an API key is a project nobody
runs, so the heuristic provider is a first-class implementation rather than a
stub: it produces genuinely useful triage and rule drafts using domain rules
about ATT&CK, LOLBins and process ancestry.

Set ``OPENAI_API_KEY`` (optionally ``PURPLEFORGE_AI_MODEL``) to enable the LLM
path. Any network or parsing failure falls back to heuristics rather than
breaking the run.
"""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from typing import Any


class AIProvider(ABC):
    """Interface shared by the heuristic and LLM backends."""

    name: str = "abstract"

    @abstractmethod
    def complete_json(self, system: str, user: str, fallback: dict[str, Any]) -> dict[str, Any]:
        """Return a JSON object for the prompt, or ``fallback`` on any failure."""

    @property
    def is_llm(self) -> bool:
        return False


# ------------------------------------------------------------ heuristic path

# Signals that carry real weight in triage decisions. Kept as data so the
# reasoning stays inspectable -- an analyst can see exactly why a score moved.
_SUSPICIOUS_TOKENS: dict[str, tuple[int, str]] = {
    "-enc": (18, "encoded PowerShell payload"),
    "encodedcommand": (18, "encoded PowerShell payload"),
    "-w hidden": (14, "hidden window"),
    "windowstyle hidden": (14, "hidden window"),
    "downloadstring": (20, "in-memory remote code download"),
    "downloadfile": (16, "remote file download"),
    "iex": (14, "invoke-expression execution"),
    "invoke-expression": (14, "invoke-expression execution"),
    "frombase64string": (12, "base64 decoding at runtime"),
    "bypass": (10, "execution policy bypass"),
    "delete shadows": (25, "shadow copy destruction"),
    "recoveryenabled no": (25, "recovery disabled"),
    "delete catalog": (22, "backup catalog destruction"),
    "disablerealtimemonitoring": (24, "endpoint protection disabled"),
    "add-mppreference": (18, "defender exclusion added"),
    "-p ": (8, "inline credential on command line"),
    "mimikatz": (30, "known credential dumping tool"),
    "sekurlsa": (30, "LSASS secret extraction"),
    "lsass": (20, "LSASS interaction"),
    "domain admins": (14, "privileged group enumeration"),
    "/domain": (10, "domain-scoped enumeration"),
    "-mhe=on": (10, "encrypted archive headers"),
}

_HIGH_RISK_PARENTS = {
    "winword.exe": (26, "Office process spawned a child interpreter"),
    "excel.exe": (26, "Office process spawned a child interpreter"),
    "powerpnt.exe": (24, "Office process spawned a child interpreter"),
    "outlook.exe": (22, "mail client spawned a child process"),
    "mshta.exe": (20, "HTA host spawned a child process"),
    "wscript.exe": (18, "script host spawned a child process"),
}

_CRITICAL_TACTICS = {
    "credential-access": (20, "credential access stage reached"),
    "impact": (24, "destructive impact stage reached"),
    "exfiltration": (20, "data leaving the environment"),
    "lateral-movement": (16, "attacker moving between hosts"),
    "privilege-escalation": (16, "privilege boundary crossed"),
}

# Mitigating context. Suspicious tokens alone cannot separate a real intrusion
# from sanctioned admin work, because legitimate tooling runs the same commands --
# backup software deletes shadow copies, SCCM adds Defender exclusions, CI agents
# run encoded PowerShell. What actually distinguishes them is provenance: which
# parent process launched it, which account ran it, and whether a change reference
# is attached. Scoring without these produces a queue where everything looks
# critical, which is the failure mode of naive alert scoring.
_TRUSTED_PARENTS: dict[str, tuple[int, str]] = {
    "veeamagent.exe": (-45, "launched by backup software"),
    "ccmexec.exe": (-40, "launched by SCCM management agent"),
    "teamcityagent.exe": (-38, "launched by CI build agent"),
    "msmpeng.exe": (-40, "Defender engine is the acting process"),
    "jenkins.exe": (-38, "launched by CI build agent"),
    "puppet.exe": (-35, "launched by configuration management"),
    "ansible.exe": (-35, "launched by configuration management"),
}

_SERVICE_ACCOUNT_PREFIXES = ("svc_", "sa_", "srv_")

_CHANGE_REFERENCE = re.compile(r"\b(cab|chg|change|ticket|inc|rfc)[-_ ]?\d{3,}\b", re.IGNORECASE)

_SCOPED_FLAGS = (
    "/for=",       # vssadmin limited to one volume rather than /all
    "/oldest",     # snapshot rotation, not wholesale destruction
)


class HeuristicProvider(AIProvider):
    """Deterministic domain-rule engine used when no LLM is configured.

    Deterministic output is a feature here, not just a fallback: the test suite
    can assert on triage scores, and two runs of the same scenario produce the
    same queue ordering.
    """

    name = "heuristic"

    def complete_json(self, system: str, user: str, fallback: dict[str, Any]) -> dict[str, Any]:
        # Heuristic reasoning happens in the callers, which have structured data
        # available. Returning the fallback keeps a single code path for both
        # providers instead of duplicating logic.
        return fallback

    # -- triage scoring ------------------------------------------------------

    def score_alert(self, context: dict[str, Any]) -> dict[str, Any]:
        """Score one alert from 0-100 with an auditable reason list."""
        severity_base = {"info": 5, "low": 20, "medium": 40, "high": 60, "critical": 75}
        score = severity_base.get(str(context.get("severity", "medium")).lower(), 40)
        reasons: list[str] = [f"rule severity is {context.get('severity', 'medium')}"]

        cmdline = str(context.get("command_line", "")).lower()
        for token, (weight, why) in _SUSPICIOUS_TOKENS.items():
            if token in cmdline:
                score += weight
                if why not in reasons:
                    reasons.append(why)

        parent = str(context.get("parent_name", "")).lower()
        if parent in _HIGH_RISK_PARENTS:
            weight, why = _HIGH_RISK_PARENTS[parent]
            score += weight
            reasons.append(why)

        # --- mitigating signals ---
        mitigated = False

        if parent in _TRUSTED_PARENTS:
            weight, why = _TRUSTED_PARENTS[parent]
            score += weight
            reasons.append(why)
            mitigated = True

        if _CHANGE_REFERENCE.search(cmdline):
            score -= 25
            reasons.append("command line cites a change or ticket reference")
            mitigated = True

        if any(flag in cmdline for flag in _SCOPED_FLAGS):
            score -= 20
            reasons.append("destructive command is scoped rather than global")
            mitigated = True

        user = str(context.get("user", "")).lower()
        if user.startswith(_SERVICE_ACCOUNT_PREFIXES):
            # Service accounts are a weak signal on their own: operators target
            # them precisely because their activity is expected. Only discount
            # when the surrounding context is also benign.
            if mitigated or int(context.get("correlated_alert_count", 0)) == 0:
                score -= 15
                reasons.append("known service account with no corroborating activity")

        if str(context.get("source_ip_scope", "")) == "internal":
            score -= 12
            reasons.append("source address is inside the corporate network")

        tactic = str(context.get("tactic", "")).lower()
        if tactic in _CRITICAL_TACTICS:
            weight, why = _CRITICAL_TACTICS[tactic]
            score += weight
            reasons.append(why)

        if context.get("integrity_level", "").lower() in {"system", "high"}:
            score += 10
            reasons.append("running at elevated integrity")

        # Correlation is the strongest single signal available. An alert that is
        # one of several on the same host is far more likely to be a real
        # intrusion than an isolated firing.
        correlated = int(context.get("correlated_alert_count", 0))
        if correlated >= 5:
            score += 20
            reasons.append(f"{correlated} related alerts on the same host")
        elif correlated >= 2:
            score += 10
            reasons.append(f"{correlated} related alerts on the same host")

        distinct_tactics = int(context.get("distinct_tactics_on_host", 0))
        if distinct_tactics >= 3:
            score += 15
            reasons.append(f"activity spans {distinct_tactics} attack tactics on this host")

        score = max(0, min(100, score))

        if score >= 80:
            verdict, action = "likely_true_positive", "escalate to incident response now"
        elif score >= 55:
            verdict, action = "suspicious", "investigate within the hour"
        elif score >= 30:
            verdict, action = "needs_context", "queue for analyst review"
        else:
            verdict, action = "likely_benign", "monitor, no action required"

        return {
            "risk_score": score,
            "verdict": verdict,
            "recommended_action": action,
            "reasoning": reasons,
            "provider": self.name,
        }


# ------------------------------------------------------------------ LLM path


class LLMProvider(AIProvider):
    """OpenAI-compatible chat completion backend.

    Wraps the heuristic provider so a failed request still returns something
    useful. Also exposes ``score_alert`` by delegation, letting callers treat the
    two providers interchangeably.
    """

    name = "llm"

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.model = model or os.environ.get("PURPLEFORGE_AI_MODEL", "gpt-4o-mini")
        self.base_url = (base_url or os.environ.get("PURPLEFORGE_AI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.timeout = timeout
        self._heuristic = HeuristicProvider()
        self.last_error: str | None = None

    @property
    def is_llm(self) -> bool:
        return True

    def score_alert(self, context: dict[str, Any]) -> dict[str, Any]:
        """Heuristic score first, then ask the model to refine the narrative.

        The numeric score stays heuristic and the model contributes analyst-facing
        reasoning. Keeping the number deterministic means the alert queue ordering
        does not drift between runs, which matters for a tool people rely on.
        """
        base = self._heuristic.score_alert(context)

        system = (
            "You are a senior SOC analyst performing alert triage. "
            "Respond with a single JSON object and no prose. Keys: "
            "'assessment' (two sentences on what this activity most likely is), "
            "'investigation_steps' (array of 3 concrete next actions), "
            "'attack_stage' (short phrase)."
        )
        user = json.dumps({"alert": context, "preliminary_score": base["risk_score"]}, indent=2)

        enrichment = self.complete_json(system, user, fallback={})
        if enrichment:
            base["assessment"] = enrichment.get("assessment")
            base["investigation_steps"] = enrichment.get("investigation_steps", [])
            base["attack_stage"] = enrichment.get("attack_stage")
            base["provider"] = f"{self.name}:{self.model}"
        return base

    def complete_json(self, system: str, user: str, fallback: dict[str, Any]) -> dict[str, Any]:
        try:
            import httpx
        except ImportError:
            self.last_error = "httpx is not installed"
            return fallback

        try:
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            return _extract_json(content) or fallback
        except Exception as exc:  # noqa: BLE001 - any failure must degrade, not crash
            self.last_error = f"{type(exc).__name__}: {exc}"
            return fallback


def _extract_json(text: str) -> dict[str, Any] | None:
    """Pull a JSON object out of a model response, tolerating code fences."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group())
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def get_provider(prefer_llm: bool = True) -> AIProvider:
    """Return the best available provider.

    Falls back to heuristics when no key is present, so the pipeline always runs.
    """
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if prefer_llm and api_key:
        return LLMProvider(api_key=api_key)
    return HeuristicProvider()
