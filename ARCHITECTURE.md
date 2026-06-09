# RemediAX v2.0 — Architecture

## Pipeline Flow
User/Developer → remediax scan --target <URL>
→ Agent 5 Orchestrator (Claude API, coordinates all agents)
→ Agent 1 Scanner (Garak + PyRIT)
   - Single-turn: 50+ probe scans
   - Multi-turn: Crescendo attacks  
   - Maps to OWASP LLM Top 10
   - Output: findings.json
→ findings.json passes to Agent 2
→ Agent 2 Remediator (LLM Guard + NeMo + Claude API)
   - LLM Guard: input/output scanners
   - NeMo: Colang dialog rails
   - Claude API: smart mapping
   - Output: guardrails.yaml
→ Normalize: map all results to OWASP LLM Top 10 unified schema
→ Agent 3 Reporter (Claude API + Jinja2)
   - Unique context per finding
   - Before/after benchmark
   - Professional HTML report
   - Output: summary.html
→ summary.html passes to Agent 4
→ Agent 4 Verifier (Promptfoo + Garak re-scan)
   - Auto-generates regression tests
   - Runs in GitHub Actions CI
   - Fails PR on regression
   - Output: benchmark.json

## Output Artifacts
- findings.json     → All attack results
- guardrails.yaml   → Auto-gen defenses
- summary.html      → HTML report
- benchmark.json    → Before/after stats
All artifacts committed to GitHub
Auto-deployed to remediax.streamlit.app

## Agent 6 — CVE Watcher (runs nightly)
Sources:
- NVD API (NIST)
- MITRE ATLAS
- OWASP Updates
- Garak new probes
- GitHub Advisories
Process:
New CVE → Claude API analyzes → generates probe
→ tests target → updates guardrails → alerts user
Fully automated — RemediAX never becomes outdated

## Agents Folder Structure
agents/
├── orchestrator.py      # Agent 5 - Claude API brain
├── scanner_agent.py     # Agent 1 - Garak + PyRIT
├── remediator_agent.py  # Agent 2 - LLM Guard + NeMo
├── reporter_agent.py    # Agent 3 - Claude API + Jinja2
├── verifier_agent.py    # Agent 4 - Promptfoo
└── cve_watcher.py       # Agent 6 - NVD + MITRE nightly

## Tools Folder Structure
tools/
├── garak_runner.py      # EXISTS - already integrated
├── pyrit_runner.py      # CREATE - Phase 2
├── llmguard_runner.py   # CREATE - Phase 2
├── nemo_runner.py       # CREATE - Phase 2
└── promptfoo_runner.py  # CREATE - Phase 2

## Schemas
schemas/
└── finding.py           # Unified Finding dataclass

## Config
config.py                # All agent configuration

## Build Order (strict)
1. schemas/finding.py first
2. config.py second
3. Agent 1 Scanner - build + test standalone
4. Agent 2 Remediator - build + test standalone
5. Agent 3 Reporter - build + test standalone
6. Agent 4 Verifier - build + test standalone
7. Agent 5 Orchestrator - connect all agents
8. Agent 6 CVE Watcher - independent schedule

## Rules
- Build and test each agent standalone first
- Connect agents only after individual testing
- Never break existing Streamlit app
- Never hardcode API keys
- All commits: author Nileshwari Kadgale only
- Run pytest after every change
- Keep 638+ tests passing
- Use PyPI stable releases not GitHub direct

## Phase Status
Phase 1 - Bug Fixes:
  Fix 1: guardrails.yaml ✅ DONE
  Fix 2: summary.html ✅ DONE
  Fix 3: Voice TTS ⬜ pending
  Fix 4: README.md ⬜ pending

Phase 2 - Tool Installation:
  Garak ✅ already integrated
  PyRIT ⬜ install pip install pyrit
  LLM Guard ⬜ install pip install llm-guard
  NeMo ⬜ install pip install nemoguardrails
  Promptfoo ⬜ install npm install -g promptfoo

Phase 3 - Build Agents (one by one)
Phase 4 - Ollama Integration
Phase 5 - CVE Watcher
Phase 6 - Polish + Launch
