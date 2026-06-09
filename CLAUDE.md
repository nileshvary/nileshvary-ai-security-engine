# RemediAX — AI Security Platform

## Project Context

RemediAX is a real open-source AI security
product built for production use. Anyone
building AI applications can use it to find,
fix, and verify LLM vulnerabilities automatically.

## What This Tool Does For Real Users

Any developer or security team can:
- Scan their AI application for vulnerabilities
- Get auto-generated guardrails to fix them
- Verify fixes actually work via CI pipeline
- Stay current with new CVEs automatically
- Get professional security reports
- Run it free — no API key needed for basics

## Who Uses RemediAX

1. AI/ML Engineers
   Building LLM apps who need to know
   if their app is vulnerable before shipping

2. Security Engineers
   Running LLM security audits on
   AI products for their company

3. Bug Bounty Researchers
   Finding vulnerabilities in AI systems
   like Mistral, OpenAI, Anthropic

4. DevSecOps Teams
   Adding AI security gates to CI/CD pipelines
   so every code change is security tested

5. Startups Building AI Products
   Who cannot afford commercial tools like
   Prisma AIRS ($$$) but need real security

6. Enterprise Security Teams
   Who want open-source auditable alternative
   to closed commercial AI security tools

## Why RemediAX Exists

Commercial tools (Prisma AIRS, Mindgard,
Lakera) are expensive and closed source.
Open source tools (Garak, PyRIT, Promptfoo)
each do one thing only.

RemediAX is the only free open-source tool
that does ALL of this in one pipeline:
Scan → Remediate → Verify → Report → Update

## Product Goals

1. PRODUCTIVITY
   One command replaces weeks of manual
   security testing work

2. ACCESSIBILITY
   Free forever — no vendor lock-in
   No expensive enterprise contracts

3. COMPLETENESS
   20 categories covered (OWASP LLM + ASI)
   More than any commercial tool

4. AUTOMATION
   CVE auto-update means zero maintenance
   Always current with latest threats

5. PROOF
   Before/after benchmark shows exactly
   how much safer your app is after fixes

## Real World Impact

Already proven on real target:
- Found 6 LLM07 vulnerabilities in Mistral AI
- Reported via HackerOne #3781259
- Tool works on real production AI systems
- Not just a demo — real security research

## How I Work With Claude Code

- I review every plan before approving
- Explain what you built and why
- Show output clearly after every task
- Ask before assuming anything
- Keep code production-grade quality
- Every feature must work for real users
  not just pass tests

## Definition of Done

A feature is DONE only when:
- Real user can use it without confusion
- Tests pass (680+)
- Documentation updated
- No existing features broken
- Committed and deployed to
  remediax.streamlit.app

---

# ai-security-engine

## Architecture

Pipeline flow:

```
integration_bridge  ->  remediation_engine  ->  verifier  ->  output (artifacts)
```

The `remediation_engine` package contains three sub-modules:

- `prompt_remediator` — remediates issues found in input prompts
- `response_remediator` — remediates issues found in model responses
- `guardrail_generator` — generates guardrails / policy rules

## Layout

- `src/` — all source code (one package per pipeline stage)
- `tests/` — all tests; directory layout mirrors `src/`
- `artifacts/` — pipeline output artifacts
- `logs/` — log files

## Coding conventions

- Python 3.12
- Type hints required on all function signatures (parameters and return types)
- Google-style docstrings
- `snake_case` for modules, functions, and variables; `PascalCase` for classes
- Use the standard `logging` module — never `print()` in source code

## Workflow rules for Claude

- **Always ask before installing new packages.** Do not add to dependencies or run `pip install` without explicit approval.
- Put all source code under `src/`, all tests under `tests/`.
- When adding a new pipeline stage or sub-module, create matching `tests/` package mirror.
- **Never add `Co-Authored-By` to any commit message.** Author is always Nileshwari Kadgale only.

## Project Identity
- Project: RemediAX AI Security Platform
- Owner: Nileshwari Kadgale
- GitHub: github.com/nileshvary/nileshvary-ai-security-engine
- Live: remediax.streamlit.app
- HackerOne: Report #3781259

## Before Every Task
- Read ARCHITECTURE.md first
- Read REMEDIAX.md if it exists
- Never assume file contents — always read actual files
- Show a plan and wait for approval before changes
- Ask if unclear — never guess

## Output Rules
- After every task show summary table:
  Files created/modified | Tests before | Tests after
- Run pytest after every code change
- Show test count before and after
- Report warnings even if not errors
- Never say "done" without showing proof

## Commit Rules
- Author: Nileshwari Kadgale
- Email: nileshvary@gmail.com
- Never add Co-Authored-By
- Message format: type: description, X tests passing
- Always push after committing

## Build Rules
- Follow ARCHITECTURE.md agent build order strictly
- Build one agent at a time
- Test each agent standalone before connecting
- Never break existing Streamlit app
- Keep 680+ tests passing always
- All new tools must degrade gracefully if not installed
- Never hardcode API keys — always os.environ

## Ask Before Doing
- Deleting any file
- Modifying app.py directly
- Changing database schema
- Installing packages not in requirements.txt
- Changing existing passing tests
- Force pushing to GitHub

## Architecture Build Order (strict)
1. schemas/finding.py ✅ DONE
2. config.py ✅ DONE
3. Agent 1: scanner_agent.py ✅ DONE
4. Agent 2: remediator_agent.py ← NEXT
5. Agent 3: reporter_agent.py
6. Agent 4: verifier_agent.py
7. Agent 5: orchestrator.py
8. Agent 6: cve_watcher.py
9. Connect to app.py last

## Coverage Requirements
- Must cover all OWASP LLM Top 10 (LLM01-LLM10)
- Must cover all ASI Agentic Top 10 (ASI01-ASI10)
- Total: 20 categories minimum
- Garak covers: LLM01, LLM05 (exploitation probes; test.Repeat, fully offline)
- PyRIT covers: LLM01-LLM07, LLM09, LLM10 (13 multi-turn crescendo probes)
- Both run together in scanner_agent.py
- ASI01-ASI10: all 10 covered ✅
