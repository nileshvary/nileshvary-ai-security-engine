# Phase 2 — v2.0 Scaffolding Completion

**Status:** COMPLETE
**Tests at end of Phase 2 scaffolding:** 659 passing

Phase 2 established the foundation for the RemediAX v2.0 six-agent pipeline.
No agents were connected yet — this phase created the shared schemas, config, and
installed all tool dependencies before agent construction began.

---

## Pipeline Architecture

Defined in `ARCHITECTURE.md`:

```
integration_bridge  →  remediation_engine  →  verifier  →  output (artifacts)
```

Six agents in build order:

| Agent | File | Status |
|---|---|---|
| 1. Scanner | `agents/scanner_agent.py` | DONE (Phase 2 + Agent 1) |
| 2. Remediator | `agents/remediator_agent.py` | NEXT |
| 3. Reporter | `agents/reporter_agent.py` | Pending |
| 4. Verifier | `agents/verifier_agent.py` | Pending |
| 5. Orchestrator | `agents/orchestrator.py` | Pending |
| 6. CVE Watcher | `agents/cve_watcher.py` | Pending |

---

## Shared Schema — `schemas/finding.py`

Unified `Finding` dataclass used by every pipeline stage:

```python
@dataclass
class Finding:
    probe_name: str
    detector_name: str
    attack_prompt: str
    model_response: str
    is_successful_attack: bool
    owasp_llm_category: str        # e.g. "LLM01"
    owasp_agentic_categories: list[str]  # e.g. ["ASI01", "ASI06"]
    severity: str                  # LOW | MEDIUM | HIGH | CRITICAL
    source: str                    # garak | pyrit | vector | manual
    raw_data: dict | None = None
```

Serialisation: `to_dict()` / `from_dict()` for JSON persistence.
Validation: `__post_init__` checks severity enum and OWASP code format (`LLM\d{2}` / `ASI\d{2}`).

---

## Centralised Config — `config.py`

`RemediAXConfig` dataclass with defaults for all six agents:

| Field | Default | Description |
|---|---|---|
| `claude_model` | `claude-haiku-4-5-20251001` | Model for AI-enhanced mode |
| `llmguard_enabled` | `True` | Enable LLM Guard scanner in Agent 2 |
| `nemo_enabled` | `True` | Enable NeMo Guardrails output in Agent 3 |
| `pyrit_max_turns` | `5` | Max conversation turns per PyRIT probe |
| `garak_timeout` | `300` | Seconds before Garak probe timeout |
| `scan_output_dir` | `artifacts/` | Where to write findings JSON |

`from_env()` classmethod reads from environment:
- `ANTHROPIC_API_KEY` — required for AI-enhanced mode
- `REMEDIAX_MODEL` — override the default Claude model
- `REMEDIAX_LLMGUARD` — `"0"` disables LLM Guard
- `REMEDIAX_NEMO` — `"0"` disables NeMo output

---

## Tools Installed

All five tools installed as production-grade packages.
All are optional — import guards prevent breaking the app if any one is missing.

| Tool | Version | Role in Pipeline | Import Guard |
|---|---|---|---|
| Garak | 0.15.0 | Scanner: single-turn probes (LLM01, LLM05) | `try/except ImportError` |
| PyRIT | 0.14.0 | Scanner: multi-turn crescendo attacks (LLM01-LLM10) | `try/except ImportError` |
| LLM Guard | 0.3.16 | Remediator: input/output guardrail scanner | `try/except ImportError` |
| NeMo Guardrails | 0.22.0 | Remediator: Colang dialog-rails output format | `try/except ImportError` |
| Promptfoo | 0.121.15 | Verifier: CI regression testing | `shutil.which("promptfoo")` |

---

## Summary

| Artifact | File | Purpose |
|---|---|---|
| Pipeline design | `ARCHITECTURE.md` | 6-agent pipeline definition |
| Shared schema | `schemas/finding.py` | Unified Finding dataclass |
| Centralised config | `config.py` | All agent configuration in one place |
| Tool: Garak | installed | Offline single-turn probe runner |
| Tool: PyRIT | installed | Multi-turn adversarial orchestrator |
| Tool: LLM Guard | installed | Input/output guardrail scanner |
| Tool: NeMo | installed | Colang guardrail format generator |
| Tool: Promptfoo | installed | CI regression verifier |

**Phase 2 final state: 659 tests passing, all 5 tools installed, pipeline scaffold ready.**
