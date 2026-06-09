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
