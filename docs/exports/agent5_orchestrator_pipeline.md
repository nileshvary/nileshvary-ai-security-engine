# Agent 5 — Orchestrator: Full Pipeline Automation in RemediAX

**Author:** Nileshwari Kadgale  
**Project:** [nileshvary/ai-security-engine](https://github.com/nileshvary/nileshvary-ai-security-engine)  
**Date:** 2026-06-09

---

## Contents

1. [What Is Agent 5 — Orchestrator?](#1-what-is-agent-5--orchestrator)
2. [Why Do We Need an Orchestrator?](#2-why-do-we-need-an-orchestrator)
3. [What Tools Does Agent 5 Use?](#3-what-tools-does-agent-5-use)
4. [How Agent 5 Works — Step by Step](#4-how-agent-5-works--step-by-step)
5. [PipelineResult — The Unified Output Object](#5-pipelineresult--the-unified-output-object)
6. [The CI Gate — One Exit Code for Everything](#6-the-ci-gate--one-exit-code-for-everything)
7. [Artifacts Written to Disk](#7-artifacts-written-to-disk)
8. [Dependency Injection — Why Every Agent Is Optional](#8-dependency-injection--why-every-agent-is-optional)
9. [CLI Usage](#9-cli-usage)
10. [Why Not n8n or Other Workflow Tools?](#10-why-not-n8n-or-other-workflow-tools)
11. [Workflow With All Agents](#11-workflow-with-all-agents)
12. [What Makes This Different From Other Security Tools?](#12-what-makes-this-different-from-other-security-tools)

---

## 1. What Is Agent 5 — Orchestrator?

Agent 5 is the **master coordinator** of the RemediAX pipeline. It is the single point
of entry for running a complete AI security audit — one command triggers the entire
chain from vulnerability discovery to verified remediation.

Before Agent 5 existed, each agent had to be called manually in sequence:

```python
# Without Agent 5 — manual, error-prone
findings = scanner.scan()
scanner.save_findings(findings, "artifacts/")

results = remediator.remediate(findings, system_prompt)
remediator.save_results(results, "artifacts/")

html = reporter.generate_report(findings, results, target)
reporter.save_report(html, "artifacts/")

report = verifier.verify(results)
verifier.save_report(report, "artifacts/")

if not verifier.ci_passed(report):
    sys.exit(1)
```

With Agent 5, all of that becomes:

```python
# With Agent 5 — one call does everything
agent = OrchestratorAgent()
result = agent.run(target="openai:gpt-4o")

if not agent.ci_passed(result):
    sys.exit(1)
```

Agent 5 lives at [agents/orchestrator.py](../../agents/orchestrator.py). Its class is
`OrchestratorAgent`.

---

## 2. Why Do We Need an Orchestrator?

### The Problem Without an Orchestrator

Before Agent 5:
- A developer had to know the correct order of all 4 agents
- Each agent's output had to be manually passed to the next
- Artifact saving was manual — easy to forget or save to the wrong path
- CI pipelines needed custom glue code for every project
- One mistake in the sequence could produce a broken report or incorrect benchmark

### What Agent 5 Solves

| Problem | Agent 5 Solution |
|---|---|
| "What order do I call agents in?" | Fixed order baked in: scan→remediate→report→verify |
| "How do I pass findings to the remediator?" | Done automatically inside `run()` |
| "Where do I save the files?" | One `artifacts_dir` parameter, all 5 files saved consistently |
| "How does CI know if the scan passed?" | Single `ci_passed` boolean on `PipelineResult` |
| "Can I test the orchestration logic?" | DI pattern — mock any sub-agent in tests |
| "Can I use a subset of agents?" | Yes — inject custom agents, disable saves, etc. |

### The Principle: Thin Coordinator

Agent 5 does **not** contain any security logic. It does not scan, remediate, report,
or verify. It only:

1. Constructs default agents if none are injected
2. Calls them in the correct order
3. Passes outputs from one agent to the next
4. Saves artifacts to disk
5. Assembles the `PipelineResult` summary

All security intelligence stays in the individual agents. This keeps Agent 5 easy to
test and easy to extend.

---

## 3. What Tools Does Agent 5 Use?

Agent 5 itself uses only Python standard library tools. Its power comes entirely from
**coordinating the four existing agents**, each of which brings its own toolchain.

### Tools Available Through Agent 5 (via sub-agents)

| Sub-Agent | Tools Used | What They Contribute |
|---|---|---|
| Agent 1 (Scanner) | Garak, PyRIT, VectorPoisoner | Discovers vulnerabilities (OWASP LLM Top 10 + ASI Top 10) |
| Agent 2 (Remediator) | LLM Guard, NeMo Guardrails, Claude API | Generates fixes — prompt patches, sanitization, guardrail YAML |
| Agent 3 (Reporter) | Jinja2, Claude API | Produces professional HTML security report |
| Agent 4 (Verifier) | QuickVerifier (heuristic), FullVerifier (Garak re-scan, v1.1) | Measures before/after improvement, provides CI gate |

### What Agent 5 Uses Directly

| Tool / Library | Why |
|---|---|
| `dataclasses` (stdlib) | `PipelineResult` frozen dataclass — flat, JSON-serialisable |
| `json` (stdlib) | `pipeline_summary.json` serialisation |
| `pathlib.Path` (stdlib) | Platform-safe artifact paths on Windows, Linux, macOS |
| `logging` (stdlib) | Per-stage progress logging (never `print()`) |
| `argparse` (stdlib) | CLI `--target`, `--system-prompt`, `--artifacts-dir`, `--no-save` |

No new packages were added. Agent 5 is entirely standard library + sub-agents.

---

## 4. How Agent 5 Works — Step by Step

### The `run()` Method

```python
result = agent.run(
    target="openai:gpt-4o",
    system_prompt="You are a helpful assistant.",
    garak_probes=None,     # None = run all default probes
    pyrit_probes=None,     # None = run all default PyRIT scenarios
    save_artifacts=True,   # write all 5 files to artifacts/
)
```

Internally, `run()` executes four sequential stages:

---

### Stage 1 — Scan

```
ScannerAgent.scan(garak_probes, pyrit_probes)
    ↓
list[Finding]   ← normalised Finding objects with OWASP LLM category
```

The scanner runs Garak and PyRIT in sequence, deduplicates results by
`(probe_name, attack_prompt)`, and returns a flat list of `Finding` objects.
Every finding has a mapped OWASP LLM category (LLM01–LLM10) and severity
(CRITICAL, HIGH, MEDIUM, LOW).

Logged as:
```
INFO OrchestratorAgent: Stage 1 — scanning
INFO OrchestratorAgent: scan complete — 6 findings
```

---

### Stage 2 — Remediate

```
RemediatorAgent.remediate(findings, system_prompt)
    ↓
list[RemediationResult]   ← prompt patches, sanitization, guardrail config
```

The remediator routes each finding by OWASP category to the appropriate
fix strategy:
- LLM01/LLM07 → prompt patch (via LLM Guard + Claude API)
- LLM02/LLM05 → response sanitization (detect and scrub PII/injections)
- LLM06 → flag only (agency action recorded for review)
- LLM10 → rate limit config added to guardrail YAML
- LLM03/04/08/09 → LOG_ONLY with tool recommendations (no runtime patch possible)

Logged as:
```
INFO OrchestratorAgent: Stage 2 — remediating
INFO OrchestratorAgent: remediation complete — 6 results
```

---

### Stage 3 — Report

```
ReporterAgent.generate_report(findings, results, target)
    ↓
str   ← full HTML report (~400–800 lines of styled HTML)
```

The reporter merges the original findings with the remediation results into a
professional 8-section HTML security report. Each finding gets a card with:
- Danger level (Claude API, or fallback)
- What was fixed (Claude API, or fallback)
- Guardrail YAML to copy-paste
- OWASP category badge and severity

Logged as:
```
INFO OrchestratorAgent: Stage 3 — generating report
INFO OrchestratorAgent: report generated (42381 chars)
```

---

### Stage 4 — Verify

```
VerifierAgent.verify(results)
    ↓
VerificationReport   ← per-finding before/after rates, improvement %, CI gate
```

The verifier inspects every `RemediationResult` artifact to estimate how much
the attack surface was reduced. Returns counts of VERIFIED / PARTIAL / FAILED /
UNVERIFIABLE results plus a severity-weighted overall improvement percentage.

Logged as:
```
INFO OrchestratorAgent: Stage 4 — verifying remediations
INFO OrchestratorAgent: pipeline complete — findings=6 verified=4 failed=0 improvement=91.2% ci_passed=True
```

---

### Artifact Persistence

After all four stages complete, Agent 5 calls each agent's `save_*()` method
to write outputs to disk under `artifacts_dir`:

```python
scanner.save_findings(findings, artifacts_dir)       # → artifacts/findings.json
remediator.save_results(results, artifacts_dir)       # → artifacts/remediation_results.json
reporter.save_report(html, artifacts_dir)             # → artifacts/summary.html
verifier.save_report(report, artifacts_dir)           # → artifacts/benchmark.json
# Agent 5 also writes its own summary:               # → artifacts/pipeline_summary.json
```

All paths are stored in `PipelineResult.artifacts` so the CI script can locate
each file without guessing.

---

## 5. PipelineResult — The Unified Output Object

`PipelineResult` is a **frozen dataclass** — all fields are set once at the end
of `run()` and never mutated. It is deliberately flat (no nested dataclasses)
so it serialises to JSON with no custom helpers.

```python
@dataclass(frozen=True)
class PipelineResult:
    target: str                         # "openai:gpt-4o"
    finding_count: int                  # 6
    remediation_count: int              # 6
    verified_count: int                 # 4
    partial_count: int                  # 1
    failed_count: int                   # 0
    unverifiable_count: int             # 1
    overall_improvement_percent: float  # 91.2
    ci_passed: bool                     # True (failed_count == 0)
    artifacts: dict[str, str]           # label → absolute path string
```

### The `artifacts` Dictionary

```python
result.artifacts == {
    "findings":              "artifacts/findings.json",
    "remediation_results":   "artifacts/remediation_results.json",
    "html_report":           "artifacts/summary.html",
    "benchmark":             "artifacts/benchmark.json",
}
```

### Saving and Loading the Summary

```python
# Save to disk
agent.save_pipeline_result(result, "artifacts/pipeline_summary.json")

# Load in a CI script — no RemediAX imports needed
import json
data = json.load(open("artifacts/pipeline_summary.json"))
print(data["ci_passed"])                      # True / False
print(data["overall_improvement_percent"])    # 91.2
print(data["artifacts"]["html_report"])       # artifacts/summary.html
```

---

## 6. The CI Gate — One Exit Code for Everything

The entire RemediAX pipeline collapses to a single boolean: **did the scan pass?**

```python
if not agent.ci_passed(result):
    sys.exit(1)   # ← CI fails — at least one remediation did not verify
```

`ci_passed` is `True` when `failed_count == 0`. The definition of failure:

| Verification Status | Blocks CI? | Meaning |
|---|---|---|
| VERIFIED | No | Fix confirmed working |
| PARTIAL | No | Partial improvement — not blocking |
| FAILED | **Yes** | Fix produced no measurable improvement |
| UNVERIFIABLE | No | Out-of-band category (LLM03/04/08/09) — needs infra work |

### GitHub Actions (When Integrated)

```yaml
# .github/workflows/remediax.yml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run RemediAX full pipeline
        run: python -m agents.orchestrator --target openai:gpt-4o
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

      - name: Check security gate
        run: |
          python -c "
          import json, sys
          d = json.load(open('artifacts/pipeline_summary.json'))
          print(f'Improvement: {d[\"overall_improvement_percent\"]}%')
          print(f'CI passed: {d[\"ci_passed\"]}')
          if not d['ci_passed']:
              print(f'FAILED: {d[\"failed_count\"]} remediation(s) did not verify')
              sys.exit(1)
          "

      - name: Upload security report
        uses: actions/upload-artifact@v4
        with:
          name: remediax-report
          path: artifacts/
```

---

## 7. Artifacts Written to Disk

Agent 5 writes 5 files per run. Every file is plain text so they can be read,
diffed, and committed to git without any tooling.

| File | Format | Written By | Purpose |
|---|---|---|---|
| `artifacts/findings.json` | JSON | Agent 1 (Scanner) | Raw vulnerability findings with OWASP categories |
| `artifacts/remediation_results.json` | JSON | Agent 2 (Remediator) | Prompt patches, sanitization, guardrail configs |
| `artifacts/summary.html` | HTML | Agent 3 (Reporter) | Human-readable 8-section security report |
| `artifacts/benchmark.json` | JSON | Agent 4 (Verifier) | Before/after rates, improvement %, CI gate |
| `artifacts/pipeline_summary.json` | JSON | Agent 5 (Orchestrator) | High-level counts + ci_passed for CI scripts |

### Default Artifact Directory

```python
OrchestratorAgent()                         # → artifacts/  (default)
OrchestratorAgent(artifacts_dir="reports")  # → reports/
OrchestratorAgent(artifacts_dir=Path("ci/outputs"))  # → ci/outputs/
```

The directory and all parent directories are created automatically if they do
not exist. No manual `mkdir` required.

---

## 8. Dependency Injection — Why Every Agent Is Optional

Agent 5 uses the same DI (Dependency Injection) pattern as all other agents:
every sub-agent is an optional constructor parameter.

```python
# Fully default — constructs all 4 agents fresh
agent = OrchestratorAgent()

# Custom verifier only — useful for testing
agent = OrchestratorAgent(verifier=my_custom_verifier)

# All mocked — used in unit tests
agent = OrchestratorAgent(
    scanner=mock_scanner,
    remediator=mock_remediator,
    reporter=mock_reporter,
    verifier=mock_verifier,
)
```

### Why DI Matters

**Without DI:** To test Agent 5, you would need a real Garak installation, real
PyRIT scenarios, a real Anthropic API key, and a live LLM endpoint. Tests would
be slow, expensive, and non-deterministic.

**With DI:** Tests inject mocks that return pre-built results instantly. The 30
tests in [tests/agents/test_orchestrator_agent.py](../../tests/agents/test_orchestrator_agent.py)
run in under 1 second and cost zero tokens.

**For users:** DI also means any sub-agent can be replaced with a custom
implementation. If a user has their own scanner, they can inject it and still
get the benefit of Agent 5's orchestration, artifact saving, and CI gate.

---

## 9. CLI Usage

Agent 5 includes a standalone CLI so it can be called directly from a terminal
or CI pipeline without writing any Python:

```bash
# Minimal — run all default probes against a target
python -m agents.orchestrator --target openai:gpt-4o

# With system prompt — used for contextual prompt patches
python -m agents.orchestrator \
    --target openai:gpt-4o \
    --system-prompt "You are a helpful customer support assistant."

# Custom output directory
python -m agents.orchestrator \
    --target openai:gpt-4o \
    --artifacts-dir ci/security-outputs/

# Dry run — run all stages but don't write any files
python -m agents.orchestrator \
    --target openai:gpt-4o \
    --no-save
```

### CLI Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--target` | Yes | — | Target identifier (e.g. `openai:gpt-4o`, URL) |
| `--system-prompt` | No | `""` | System prompt of the target LLM |
| `--artifacts-dir` | No | `artifacts` | Directory for output files |
| `--no-save` | No | False | Skip writing artifact files |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Pipeline passed — `ci_passed = True` (no FAILED verifications) |
| `1` | Pipeline failed — at least one remediation did not verify |

This matches the Unix convention so any CI system can use it directly:

```bash
python -m agents.orchestrator --target openai:gpt-4o || echo "Security gate failed!"
```

---

## 10. Why Not n8n or Other Workflow Tools?

**n8n** is a visual workflow automation tool (like Zapier/Make but self-hosted).
Users sometimes ask whether n8n is needed to connect the agents. The answer is no.

### What n8n Is Good For

n8n connects services over HTTP — Slack, GitHub, Jira, webhooks, databases. It is
the right tool when you need to trigger a pipeline from an external event (a PR
opened on GitHub, a message in Slack, a schedule in a cron job) and coordinate
responses across multiple independent services.

### Why n8n Is Not Needed for RemediAX

All four RemediAX agents are Python classes in the same repository. Agent 5 calls
them as direct Python function calls — no HTTP, no serialisation overhead, no
separate service.

| Question | Answer |
|---|---|
| Do the agents live in different services? | No — all in one Python repo |
| Do they communicate over HTTP? | No — direct function calls |
| Does the pipeline need a running server? | No — runs on demand, exits when done |
| Can it run in CI without a server? | Yes — `python -m agents.orchestrator` |

### When n8n Would Make Sense (Future)

If RemediAX is extended to:
- Post results to a Slack channel automatically
- File a GitHub issue when `ci_passed = False`
- Trigger a scan on every PR merge via webhook
- Schedule nightly scans via cron

...then n8n (or a simple Flask endpoint calling `OrchestratorAgent.run()`) would
be the right integration layer. That is a feature for Agent 6+ scope, not
the current pipeline.

**The rule:** Agent 5 provides the automation. n8n provides the triggers. You do
not need triggers to run the automation — triggers are optional add-ons.

---

## 11. Workflow With All Agents

### Where Agent 5 Sits in the Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                   RemediAX v2.0 Pipeline                            │
│                                                                     │
│   User / CI system                                                  │
│       │                                                             │
│       ▼                                                             │
│   OrchestratorAgent.run(target)           ← Agent 5 (YOU ARE HERE) │
│       │                                                             │
│       ├──▶  Stage 1: ScannerAgent.scan()                           │
│       │         Garak (LLM01/05/07)                                │
│       │         PyRIT (LLM01-LLM07, LLM09, LLM10)                 │
│       │         VectorPoisoner (ASI01-ASI10)                       │
│       │         → list[Finding]  +  findings.json                  │
│       │                                                             │
│       ├──▶  Stage 2: RemediatorAgent.remediate(findings)           │
│       │         LLM Guard (pre-scan enrichment)                    │
│       │         NeMo Guardrails (YAML config generation)           │
│       │         Claude API (contextual prompt patches)             │
│       │         → list[RemediationResult]  +  remediation_results.json │
│       │                                                             │
│       ├──▶  Stage 3: ReporterAgent.generate_report(...)            │
│       │         Jinja2 (HTML template engine)                      │
│       │         Claude API (per-finding danger/fix explanations)   │
│       │         → HTML string  +  summary.html                     │
│       │                                                             │
│       ├──▶  Stage 4: VerifierAgent.verify(results)                 │
│       │         QuickVerifier (heuristic, offline)                 │
│       │         FullVerifier (Garak re-scan, v1.1 planned)         │
│       │         → VerificationReport  +  benchmark.json            │
│       │                                                             │
│       └──▶  PipelineResult  +  pipeline_summary.json               │
│                 ci_passed: True / False                             │
│                 sys.exit(0) or sys.exit(1)                          │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow Between Agents

```
Target (string)
    │
    ▼
Agent 1 ─────── list[Finding] ──────────────────────────────► Agent 3
                    │                                              │
                    ▼                                             (also needs)
                Agent 2 ─── list[RemediationResult] ─────────► Agent 3
                                    │
                                    ▼
                                Agent 4 ─── VerificationReport
                                                    │
                                                    ▼
                                            PipelineResult
                                            (ci_passed bool)
```

Note: Agent 3 (Reporter) receives BOTH findings (from Agent 1) AND results
(from Agent 2). Agent 4 (Verifier) receives only results (from Agent 2).
This means Reporter and Verifier are independent of each other — they consume
Agent 2's output but do not depend on each other's output.

### What Agent 6 Will Add

Agent 6 (CVE Watcher — planned) will run independently of the pipeline. It
watches for new CVEs published to OWASP, NIST NVD, and HackerOne, and updates
the probe libraries used by Agent 1. This means RemediAX always scans for the
latest threats without any manual update.

```
Agent 6 (CVE Watcher)
    │
    └──▶  Updates probe library  ──▶  Agent 1 (Scanner) picks up new CVEs automatically
```

Agent 6 does NOT plug into `OrchestratorAgent.run()`. It is a separate scheduled
process (cron / n8n / Task Scheduler) that keeps the scan data current.

---

## 12. What Makes This Different From Other Security Tools?

### The One-Command Problem in the Industry

Every other open-source AI security tool requires multiple manual steps:

| Tool | What you must do manually |
|---|---|
| Garak | Run scan, read hitlog.jsonl, manually decide what to fix |
| PyRIT | Run orchestrator, parse results, manually write fixes |
| Promptfoo | Write YAML tests, run eval, read pass/fail table |
| LLM Guard | Deploy as API, manually route prompts through it |
| NeMo Guardrails | Write Colang config manually, test manually |

**With RemediAX Agent 5:**
```bash
python -m agents.orchestrator --target openai:gpt-4o
```
→ Scan runs → Fixes generated → HTML report created → Fixes verified → CI gate evaluated.  
Zero manual steps between discovery and proof of improvement.

### Feature Comparison

| Feature | RemediAX Agent 5 | Garak | PyRIT | Promptfoo | LLM Guard |
|---|---|---|---|---|---|
| One command for full pipeline | **YES** | No | No | No | No |
| Auto-generates fixes from scan | **YES** | No | No | No | No |
| HTML report per scan | **YES** | No | No | Yes | No |
| Before/after improvement score | **YES** | No | No | No | No |
| CI gate (exit 0/1) | **YES** | Partial | No | Yes | No |
| Saves all artifacts automatically | **YES** | No | No | Partial | No |
| Works offline / no API needed | **YES** | Yes | Yes | Partial | Yes |
| Free and open source | **YES** | Yes | Yes | Yes | Yes |
| ASI Agentic Top 10 coverage | **YES** | No | No | No | No |

### The Key Insight

Other tools answer: *"Is my app vulnerable?"*  
RemediAX Agent 5 answers: *"Is my app vulnerable, and is it fixed, and can you prove it?"*

---

*RemediAX AI Security Platform · Nileshwari Kadgale · nileshvary@gmail.com*  
*github.com/nileshvary/nileshvary-ai-security-engine · remediax.streamlit.app*
