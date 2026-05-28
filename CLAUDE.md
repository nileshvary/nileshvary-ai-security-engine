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
