# PurpleForge

A purple-team platform that measures whether your detections actually work, then
proves the measurement is trustworthy.

Red-team tools tell you an attack succeeded. Blue-team tools tell you an alert fired.
Neither answers the question that matters: **of the techniques an adversary would use
against you, how many would you catch, how much noise would you wade through to find
them, and would any of it survive an operator who changes one flag?**

```
emulate  →  detect  →  score  →  triage  →  author  →  re-score
  red      blue+corr   purple      AI         AI       verify
   ↓              ↓
attack graph   incidents + calibrated UEBA
   ↓              ↓
adaptive path  evidence lineage
                          ↓
              robustness · stability · compliance
```

---

## What makes this different

Most detection-coverage tooling grades itself and reports a single flattering number.
Six design decisions exist specifically to prevent that:

**Ground truth, not estimates.** Every synthetic event is labelled with the technique
that produced it. True and false positives are counted, not inferred. A rule that
fires on real attack activity but claims the *wrong* technique earns no credit —
catching the right event for the wrong reason is still noise.

**Benign noise that can actually trip the rules.** The emulator mixes in sanctioned
admin work that resembles an attack: Veeam deleting shadow copies, SCCM adding
Defender exclusions, CI agents running encoded PowerShell, help desk staff using
PsExec. Without these, no benign event could ever match a rule, precision would be
1.0 by construction, and the scorecard would be theatre.

**Confidence intervals, not point estimates.** Metrics are sampled across many seeds
with bootstrap CIs. On the bundled content, recall is perfectly stable but precision
ranges 0.375–0.562 and **the letter grade flips between D and F depending on the
seed**. A single run cannot tell you that, and quoting one run's precision to three
decimals implies confidence the measurement does not support.

**Adversarial robustness testing.** Rules are attacked with behaviour-preserving
mutations — case flipping, `de""lete`, `delete^ shadows`, flag abbreviation. None
change what the command does, so a rule that stops firing was matching the *spelling*
of a technique, not the technique. This found 5 fragile rules in the initial set.

**A holdout split on the AI-generated rules.** Rules drafted from telemetry and then
graded on that telemetry always look excellent. PurpleForge re-emits every scenario
under a different seed with new C2 infrastructure and reports both numbers. This
catches a real overfit: the generated exfiltration rule recovers its technique
in-sample and **fails on holdout** because it latched onto a hardcoded C2 domain.
That result is reported rather than tuned away.

**Control status derived from evidence.** NIST 800-53, NIST CSF 2.0 and ISO 27001
controls are marked effective only where every mapped technique was actually detected
during emulation — not because a tool is licensed.

**Adaptive offense without weaponization.** A multi-objective Dijkstra/A* planner
models enterprise hosts, directed reachability, credential gates, defensive controls,
operational cost, and detection risk. Simulated blue-team feedback penalizes an
exposed route and forces replanning. It is deliberately metadata-only: no commands,
sockets, authentication attempts, exploits, sleeps, or network traffic exist in the
implementation.

**Operational defense with auditable evaluation.** Alerts are reconstructed into
incidents through an entity/time graph with deterministic IDs, evidence lineage,
duplicate-safe risk, confidence, and ATT&CK tactic progression. Ground truth is kept
in a separate evaluation field and never influences construction or ranking. A
per-user behavioral model uses Welford statistics plus median/MAD, learns only from
an explicit benign calibration period, and scores a holdout without updating itself—
preventing the event under judgment from poisoning its own baseline.

---

## Install

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate
pip install -e ".[dev]"
```

## Run

```bash
purpleforge run --html --navigator --stability 12
```

No API key needed. With none set, the AI layer uses a local deterministic engine that
produces genuinely useful triage and rule drafts. Set `OPENAI_API_KEY` to route
reasoning through an LLM instead.

### Commands

```bash
purpleforge run --html --json --navigator     # full assessment
purpleforge run --no-advanced                  # faster core-loop iteration
purpleforge run --stability 20                 # with confidence intervals
purpleforge attack-path                        # safe baseline/adaptive graph simulation
purpleforge attack-path --objective FILE-01 --cost-weight 1 --risk-weight 4
purpleforge incidents --output out/incidents.json   # incident + evidence lineage
purpleforge behavioral --output out/behavioral.json # calibrated holdout UEBA
purpleforge robustness                        # adversarial evasion testing
purpleforge stability --runs 25               # metric distributions
purpleforge compliance --framework ISO        # control effectiveness
purpleforge scenarios                         # list adversary chains
purpleforge rules                             # list and syntax-check detections
purpleforge validate --min-robustness 0.85    # CI gate
```

### Outputs

| Flag | Artifact |
|---|---|
| *(default)* | Rich terminal report |
| `--html` | Standalone HTML report, CSS inlined |
| `--json` | Full machine-readable result |
| `--navigator` | [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer |
| `--write-rules DIR` | AI rule drafts as disabled Sigma-style YAML |

---

## Sample output

```
Grade: D   F1: 0.51   Technique recall: 61%   Precision: 44%
Techniques: 11/18      Alerts: 41             TP / FP: 18 / 23

Metric Stability (15 seeds)
  technique recall   0.611   CI [0.611, 0.611]   stable
  precision          0.472   CI [0.444, 0.499]   moderate
  f1 score           0.531   CI [0.512, 0.548]   moderate
  Modal grade D (Dx11, Fx4)
  Grade is not stable across seeds; the interval is the citable result.

Adversarial Robustness
  Robustness: 91%   Cases tested: 96   Evasions: 9   Fragile rules: 4
  x PF-R-0001 (67% survival) defeated by caret_escape, quote_insertion

Control Effectiveness
  NIST SP 800-53       71%    6 effective  5 partial  1 ineffective
  NIST CSF 2.0         70%    4 effective  6 partial  0 ineffective
  ISO/IEC 27001:2022   70%    5 effective  4 partial  1 ineffective

Effect of AI-Drafted Rules
  Baseline rules             61%   44%   0.51   D
  + AI rules (in-sample)    100%   52%   0.68   C
  + AI rules (holdout)       94%   53%   0.68   C
  6 recovered and generalised | 1 overfit: T1041

Advanced Offensive + Defensive Analysis
  Baseline route  DMZ-WEB-01 -> BUILD-01 -> DC-01
  Adaptive route  DMZ-WEB-01 -> JUMP-01 -> FILE-01 -> DC-01
  Alerts 41 -> Incidents 6 (6.83:1 compression)
  Behavioral holdout  precision 57.14% | recall 26.67% | TP / FP 8 / 6
```

The advanced results are intentionally imperfect. In the reference run, incident
reconstruction compresses 41 alerts into 6 evidence-backed cases, while behavioral
analytics catches only about 27% of attack events and flags 6 benign events. That is
a measured baseline and engineering backlog—not a claim that anomaly detection is
production-ready.

The grade is **D on purpose**. A rule set scoring an A out of the box would mean the
scenarios were written to match the rules, which is the failure mode this design
exists to avoid.

---

## Architecture

```
src/purpleforge/
├── models.py                    Domain types, ECS-style events, ground-truth logic
├── pipeline.py                  Orchestrator, holdout eval, stability sampling
├── cli.py                       10 subcommands
├── emulation/                   RED
│   ├── scenario.py              YAML scenario loading
│   ├── emitter.py               Synthetic telemetry + benign lookalike noise
│   ├── evasion.py               Adversarial mutation harness
│   └── scenarios/               3 adversary chains, 18 ATT&CK techniques
├── detection/                   BLUE
│   ├── engine.py                Sigma-style matcher, recursive-descent parser
│   ├── correlation.py           Stateful sequence/threshold/distinct rules
│   ├── rules/                   10 single-event analytics
│   └── correlations/            4 multi-event analytics
├── scoring/                     PURPLE
│   ├── scorecard.py             Precision, recall, F1, gaps, tuning backlog
│   ├── statistics.py            Bootstrap CIs, significance testing
│   └── compliance.py            NIST 800-53 / CSF 2.0 / ISO 27001 mapping
├── offensive/                   SAFE RED REASONING
│   ├── environment.py           Hosts, reachability, credentials, controls
│   ├── planner.py               Multi-objective Dijkstra/A* attack graph
│   └── adaptive.py              Detection feedback + inert timing metadata
├── defensive/                   ADVANCED BLUE
│   ├── baseline.py              Welford + median/MAD behavioral baselines
│   └── incidents.py             Entity/time graph + evidence lineage
├── ai/                          AI
│   ├── provider.py              Heuristic + LLM backends, graceful degradation
│   ├── triage.py                Correlation-aware alert scoring
│   └── rule_author.py           Rule generation with validation guardrails
└── reporting/                   Console, HTML, ATT&CK Navigator
```

### Adversary scenarios

| ID | Scenario | Why it's included |
|---|---|---|
| `PF-APT29-01` | APT29 spearphishing → domain credential theft | Seven tactics of individually plausible steps; punishes single-indicator analytics |
| `PF-RANSOM-01` | LockBit-style human-operated ransomware | Destructive stages are trivial to detect but far too late; tests the quiet preparation window |
| `PF-INSIDER-01` | Departing insider IP theft | Sanctioned tooling, legitimate access, nothing malicious in isolation — only correlation catches it |

### Correlation engine

Single-event rules cannot express the individually-benign-but-collectively-malicious
pattern, which is exactly how competent operators stay under the threshold. Three
shapes cover most production correlation logic:

- **sequence** — ordered stages within a window on a shared key (kill-chain progression)
- **threshold** — N matches in a window (brute force, where volume is the signal)
- **distinct** — N *unique* field values in a window (scanning, distinguishable from
  a misconfigured client retrying one host — a plain threshold conflates the two)

Windows are mandatory and bounded. An unbounded correlation eventually matches any
event set, producing impressive recall and no detection value.

Correlation raised recall from 50% to 61% **and improved precision**, catching
T1134.001 and T1567.002 which no single-event rule could.

### Adaptive attack-path simulation

The reference environment is intentionally asymmetric: a weakly monitored build
server offers the cheapest baseline route, while a heavily instrumented jump host and
file server form a more expensive alternate path. The planner minimizes a weighted
sum of operational cost and detection risk while carrying immutable state for
controlled hosts and acquired credentials. Privileged edges remain unavailable until
a modelled privileged credential has been acquired; defensive controls can raise risk
or block mapped transitions entirely.

`purpleforge attack-path` exposes the model, weights, baseline plan, and adaptive plan.
By default, simulated high-confidence feedback on `BUILD-01` changes the route from
`DMZ-WEB-01 → BUILD-01 → DC-01` to
`DMZ-WEB-01 → JUMP-01 → FILE-01 → DC-01`. Timing dilation is only an annotation for
testing correlation-window assumptions. It never waits, schedules work, or executes a
transition.

### Incident reconstruction

`purpleforge incidents` builds a graph over alerts that share a host, user, or
destination inside a bounded 15-minute telemetry window. Union-find components become
incidents with deterministic IDs, deduplicated evidence risk, operational confidence,
entity sets, ATT&CK tactic progression, and alert-to-event lineage. The implementation
uses event timestamps—not batch match time—so an offline replay cannot collapse hours
of unrelated activity into one case.

Risk and confidence depend only on observable alert evidence. Ground-truth alert and
event purity appear under a separate `evaluation` object, making leakage auditable.
The bundled reference run compresses 41 alerts to 6 incidents (about 6.83:1) without
losing alert membership.

### Behavioral calibration and holdout

`purpleforge behavioral` establishes independent per-user feature baselines using a
70% benign calibration split. The remaining 30% benign events plus all attack events
form a score-only holdout: evaluation does not update the model. Welford's algorithm
provides numerically stable online variance; median/MAD reduces outlier sensitivity;
minimum-sample, zero-variance, and mature-entity feature-novelty paths are explicit.

The reference measurement uses 252 calibration and 138 evaluation events. It detects
8 attack events, flags 6 benign events, reaches about 57.14% precision, and only about
26.67% event recall. Those values are published because a useful portfolio project
should reveal where behavioral coverage needs work rather than convert anomaly volume
into a success metric.

### Statistical rigor

Bootstrap resampling rather than a normal approximation, because these metrics are
bounded to [0,1] and skewed near the extremes — a normal approximation reports upper
bounds above 1.0 for near-perfect precision. `compare()` states whether a rule change
is distinguishable from seed variance, which is the guard against celebrating a change
that did nothing.

The most actionable output is **intermittently detected techniques**: a technique
caught 60% of the time is not covered, it is covered by accident. A single run reports
it as a clean pass or a clean gap and hides the coin flip.

### Detection engine

Sigma-flavoured subset: `contains`, `startswith`, `endswith`, `re`, `gt`/`gte`,
`lt`/`lte`, `in`, `exists`. Conditions support `and`/`or`/`not`, parentheses, and
quantifiers (`all of them`, `1 of selection_*`).

Conditions are parsed with a recursive-descent parser, **never `eval`**. Rules are
untrusted input because the AI layer generates them, and passing generated strings to
`eval` would be a code-execution hole. A test asserts a Python injection payload in a
condition raises rather than executing.

### AI layer

**Triage** computes host-level correlation *before* scoring each alert. An isolated
PowerShell alert is ambiguous; the same alert on a host also showing credential access
and lateral movement is an active intrusion. Scoring alerts in isolation — what a naive
one-LLM-call-per-alert integration does — throws that signal away.

It also weighs *mitigating* context, which separates a real intrusion from sanctioned
admin work running identical commands: parent process, whether the account is a known
service account, whether a change ticket is cited, whether a destructive command was
scoped (`/for=D: /oldest`) or global (`/all`). Reported via **separation** — the gap
between mean score on real detections versus false positives.

**Rule authoring** turns coverage gaps into candidates, with two guardrails: candidates
firing on benign events are **rejected** rather than shipped with a warning, and nothing
is auto-enabled.

---

## Testing

```bash
pytest
```

**240 tests.** Beyond unit coverage, these lock in the properties that make the
assessment trustworthy:

- Benign noise **can** trip the rules, so precision is earned rather than free
- Right event + wrong technique is **not** a true positive
- A correlation built entirely from benign events is a false positive however long
- Correlation does not span hosts, reuse events, or fire outside its window
- Mutations are **semantics-preserving** (verified by reversibility), so the evasion
  harness measures rule fragility rather than changed behaviour
- Hardened rules survive all five mutation classes without becoming catch-alls
- Bootstrap intervals respect metric bounds and are reproducible
- Seed noise is **not** reported as improvement
- Untested controls report `not_assessed`, never a pass
- Conditions are parsed, not executed — injection payloads raise
- Same seed produces byte-identical telemetry, including event IDs
- Overfit rules are named individually, not folded into the headline number
- Credential gates and defensive blocks constrain graph paths
- Detection feedback changes routes without executing any offensive action
- Timing dilation remains inert metadata and cannot sleep or schedule work
- Incident windows use telemetry time, preserve every alert, and deduplicate risk
- Ground truth cannot change incident IDs, risk, confidence, or ranking
- Behavioral holdout scoring cannot contaminate its calibration baseline
- Constant baselines and newly appearing features are handled explicitly

## CI

`.github/workflows/ci.yml` runs the suite on Python 3.11–3.13, then gates on coverage,
adversarial robustness, and control coverage in the weakest framework. A commit that
weakens a rule to a literal string match fails the build.

---

## Scope and honest limitations

**No attacker code is executed.** Scenarios declare the telemetry a technique *would*
produce, and offensive planning searches an in-memory graph of descriptive ATT&CK
metadata. There are no payloads, commands, sockets, authentication attempts, credential
attacks, process launches, sleeps, or network operations. That trades fidelity to real
EDR output for runs that are safe anywhere, need no lab or agents, and reproduce
exactly from a seed. For validating detection *logic* and defensive workflow—which is
what this grades—that is the right trade.

What this means in practice:

- **Not a substitute for live-fire testing.** It will not surface EDR sensor blind
  spots, driver-level evasion, or gaps in log collection and forwarding.
- **Synthetic noise is simpler than production.** Real SOC noise is more varied and far
  higher volume. Precision here is directionally useful, not a forecast.
- **Compliance mappings are a curated subset**, covering the techniques emulated here
  rather than the full published crosswalks. Absence of a control from the report is
  not evidence about that control, and the report says so in its own scope note.
- **The evasion harness models low-effort obfuscation**, not an advanced adversary.
  Surviving it is a floor, not a ceiling.
- **Field names assume a normalisation layer.** The schema is ECS-flavoured; adapting
  rules to a specific SIEM means remapping fields.
- **Coverage is bounded by the scenarios.** 18 techniques is a meaningful
  cross-section, not the whole ATT&CK matrix. A perfect score means "detects what was
  tested."

Extending it means adding YAML — a new scenario, rule, or correlation file, no Python
changes.

## References

- [MITRE ATT&CK](https://attack.mitre.org/) — technique taxonomy
- [MITRE Engenuity CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) — ATT&CK to NIST 800-53 crosswalk
- [NIST CSF 2.0](https://www.nist.gov/cyberframework)
- [Sigma](https://github.com/SigmaHQ/sigma) — detection rule format
- [CISA AA23-165A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a) — LockBit advisory

## License

MIT
