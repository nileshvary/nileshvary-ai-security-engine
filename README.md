# RemediAX — AI Security Remediation Engine

[![CI](https://github.com/nileshvary/nileshvary-ai-security-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/nileshvary/nileshvary-ai-security-engine/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![HackerOne](https://img.shields.io/badge/HackerOne-%233781259-green.svg)](https://hackerone.com/remediax)

**RemediAX** is an AI security remediation engine that scans LLM applications for vulnerabilities, maps findings to OWASP LLM Top 10 and ASI Agentic Top 10, and auto-generates guardrails and remediation artifacts using Claude AI.



---

## What It Does

| Capability | Detail |
|---|---|
| **Scan** | Runs NVIDIA Garak probes against any LLM endpoint |
| **Map** | Maps every finding to OWASP LLM Top 10 (LLM01–LLM10) + ASI Agentic Top 10 |
| **Remediate** | Generates per-finding patches, sanitization rules, and system-prompt hardening |
| **Guardrails** | Auto-generates `guardrails.yaml` covering all 20 vulnerability categories |
| **Report** | Produces a professional HTML security report with unique per-finding analysis |
| **Verify** | Post-remediation verification confirms each fix actually blocks the attack |

---

## Architecture

```
integration_bridge  →  remediation_engine  →  verifier  →  output
       ↓                      ↓                   ↓            ↓
  Parses Garak           Prompt patch        Re-runs probe   HTML report
  hitlog → Finding       Response sanitize   → pass/fail     JSON findings
  OWASP mapping          Guardrail gen                       guardrails.yaml
                         (Claude API)
```

**Pipeline packages** (`src/`):

```
src/
├── integration_bridge/     # Garak parser, OWASP mapper, Finding model
├── remediation_engine/
│   ├── prompt_remediator/  # System-prompt patches (LLM01, LLM07)
│   ├── response_remediator/# Output sanitization (LLM02, LLM05, LLM06)
│   └── guardrail_generator/# Universal guardrails via Claude API
├── verifier/               # Post-remediation re-evaluation
└── output/                 # HTML, JSON, YAML, Markdown writers
```

---

## OWASP LLM Top 10 Coverage (2025)

| ID | Vulnerability | Coverage |
|---|---|---|
| LLM01 | Prompt Injection | ✅ Blocked — instruction hierarchy + delimiter tagging |
| LLM02 | Sensitive Information Disclosure | ✅ Redacted — PII/secrets output filter |
| LLM03 | Supply Chain | ✅ Detected — LOG_ONLY + manifest verification guidance |
| LLM04 | Data and Model Poisoning | ✅ Detected — LOG_ONLY + training audit guidance |
| LLM05 | Improper Output Handling | ✅ Sanitized — XSS/SQLi output filter |
| LLM06 | Excessive Agency | ✅ Blocked — tool-call approval guardrail |
| LLM07 | System Prompt Leakage | ✅ Hardened — non-disclosure clause + leak filter |
| LLM08 | Vector/Embedding Weaknesses | ✅ Detected — LOG_ONLY + RAG ACL guidance |
| LLM09 | Misinformation | ✅ Detected — LOG_ONLY + grounding guidance |
| LLM10 | Unbounded Consumption | ✅ Rate-limited — request/token limits enforced |

---

## Real-World Validation — Mistral AI Bug Bounty

RemediAX was used to discover **6 confirmed LLM07 (System Prompt Leakage) vulnerabilities** in [chat.mistral.ai](https://chat.mistral.ai) (Mistral Vibe, model: Mistral Medium 3.5).

| # | Probe | Attack Type | Score | Severity |
|---|---|---|---|---|
| 1 | `promptleak.PromptRepeat` | Verbatim system prompt extraction | 1.0 | MEDIUM |
| 2 | `promptleak.IndirectLeak` | Identity probing via model comparison | 1.0 | LOW |
| 3 | `promptleak.GuidelineExtraction` | Internal guideline enumeration | 0.9 | MEDIUM |
| 4 | `promptleak.RuleExtraction` | Complete rule-set extraction | 0.9 | MEDIUM |
| 5 | `promptleak.SafetyTriggerMap` | Safety filter condition mapping | 0.95 | MEDIUM |
| 6 | `promptleak.BypassMap` | Bypass phrase blueprint extraction | 0.95 | MEDIUM |

**Submitted:** HackerOne Report [#3781259](https://hackerone.com/reports/3781259) · CVSS 5.1 Medium · CWE-215 · OWASP A05:2021  
**Status:** Under review by Mistral AI security team

---

## Tech Stack

| Component | Technology |
|---|---|
| Frontend | Streamlit (Jarvis dark theme) |
| AI / Remediation | Claude API (`claude-haiku-4-5-20251001`) |
| Scanner | NVIDIA Garak |
| Backend | Python 3.12 |
| Database | Firebase Firestore |
| Auth | Fernet-encrypted API key via `?ak=` URL param |
| Caching | SHA-256 per finding |
| CI/CD | GitHub Actions → auto-deploy to Streamlit Cloud |

---

## Installation

**Requirements:** Python 3.12, pip

```bash
git clone https://github.com/nileshvary/nileshvary-ai-security-engine.git
cd nileshvary-ai-security-engine

# Install all dependencies (webapp + dev)
pip install -e ".[dev,webapp]"
```

**Set your Anthropic API key:**

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

**Run the web app locally:**

```bash
streamlit run app.py
```

---

## Generate Guardrails (CLI)

Generate a universal `guardrails.yaml` covering all OWASP LLM01–LLM10:

```bash
# AI mode — Claude authors a guardrail per finding (recommended)
python generate_guardrails.py

# Deterministic mode — no API key required
python generate_guardrails.py --deterministic
```

---

## Run the Test Suite

```bash
python -m pytest -q
# 645 tests passing
```

---

## About the Author

**Nileshwari Kadgale** — Senior Application Engineer, CCIE Security, PCNSE

9+ years in enterprise network security (Palo Alto Networks, Zero Trust, Cisco, AWS). Built RemediAX to apply defense-in-depth principles to the AI/LLM attack surface and demonstrate practical AI security research.

- GitHub: [github.com/nileshvary](https://github.com/nileshvary)
- HackerOne: [hackerone.com/remediax](https://hackerone.com/remediax)
