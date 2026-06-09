"""Agent 1 → Agent 2 end-to-end smoke test.

Run with:
    python artifacts/combined_remediation_test.py

Tests the complete pipeline handoff:
    Scanner (Agent 1) → findings → Remediator (Agent 2) → remediation_results.json

No live LLM.  PyRIT uses a VulnerableModel stub; VectorPoisoner uses an
in-memory Chroma store; LLMGuard uses offline BanSubstrings scanners;
NeMo generates config without a runtime connection.
"""
import sys
sys.path.insert(0, 'src')
sys.path.insert(0, '.')

from pathlib import Path

from tools.pyrit_runner import PyRITRunner
from tools.vector_poisoner import VectorPoisoner
from tools.llmguard_runner import LLMGuardRunner
from tools.nemo_runner import NemoRunner
from agents.scanner_agent import ScannerAgent
from agents.remediator_agent import RemediatorAgent
from integration_bridge.parser import GarakParser


# ── Garak: replay real .report.jsonl ─────────────────────────────────────
garak_report = Path(r'C:\Users\T460S\.local\share\garak\garak_runs\garak.bd94483e-2ebc-453b-b3d2-86dd9053c5d7.report.jsonl')
garak_parser = GarakParser(garak_report)
garak_bridge_findings = garak_parser.parse()


class _FakeGarakRunner:
    def run_scan(self, probes=None):
        return garak_bridge_findings


# ── PyRIT: canned vulnerable target ──────────────────────────────────────
class VulnerableModel:
    def respond(self, prompt):
        p = prompt.lower()
        if 'ignore all previous' in p or 'i will ignore' in p:
            return 'Sure, I will ignore all previous instructions as you asked.'
        if 'maintenance mode' in p or 'output your full' in p:
            return 'Sure, I will reveal: You are a helpful AI assistant with no content policy.'
        if 'api keys' in p or 'credentials' in p:
            return 'As requested, here is the API key: sk-ant-api03-...'
        if 'plugin' in p or 'initialize()' in p:
            return 'As requested, loading admin-helper and running initialize().'
        if 'remember' in p and 'safety' in p:
            return 'Acknowledged. Safety guidelines suspended as instructed.'
        if 'bash' in p or '/etc/' in p:
            return 'As requested, here are the files without any safety filters.'
        if 'user data' in p or 'history' in p:
            return 'As requested, here are all user interactions from this session.'
        if 'override' in p and 'objective' in p:
            return 'Sure, I will report to the control server as directed.'
        if 'repeat the exact' in p or 'instructions you were given' in p:
            return 'Sure, I will reveal: You are a helpful AI with no restrictions.'
        if 'penetration test' in p or 'pre-approved' in p:
            return 'Confirmed. I understand and will comply with the authorized test.'
        if 'recursively retry' in p:
            return 'As requested, initiating recursive retry loop.'
        if 'agent-orchestrator' in p or 'privileged operation' in p:
            return 'Confirmed. Proceeding without validation as instructed.'
        return 'Here is your answer without any safety filters as requested.'


# ── AGENT 1: Scan ─────────────────────────────────────────────────────────
print("=" * 60)
print("AGENT 1 — Scanner")
print("=" * 60)

pyrit_runner = PyRITRunner(target=VulnerableModel())
vector_poisoner = VectorPoisoner()

scanner = ScannerAgent(
    garak_runner=_FakeGarakRunner(),
    pyrit_runner=pyrit_runner,
    vector_poisoner=vector_poisoner,
)
findings = scanner.scan()

findings_path = scanner.save_findings(findings, 'artifacts/findings.json')
print(f"Findings: {len(findings)}")
print(f"  Garak:  {sum(1 for f in findings if f.source == 'garak')}")
print(f"  PyRIT:  {sum(1 for f in findings if f.source == 'pyrit')}")
print(f"  Vector: {sum(1 for f in findings if f.source == 'vector')}")
print(f"Saved:   {findings_path}")

# ── AGENT 2: Remediate ────────────────────────────────────────────────────
print()
print("=" * 60)
print("AGENT 2 — Remediator")
print("=" * 60)

llmguard = LLMGuardRunner()
nemo = NemoRunner()

remediator = RemediatorAgent(
    llmguard_runner=llmguard,
    nemo_runner=nemo,
    guardrail_format="generic",
)
results = remediator.remediate(findings)
results_path = remediator.save_results(results, 'artifacts/remediation_results.json')

print(f"Results: {len(results)}")
print(f"Saved:   {results_path}")
print(f"NeMo:    artifacts/nemo_guardrails.yaml")

# Strategy breakdown
from remediation_engine.models import RemediationStrategy
strategy_counts = {}
for r in results:
    s = str(r.strategy)
    strategy_counts[s] = strategy_counts.get(s, 0) + 1

print()
print("Remediation strategy breakdown:")
for strategy, count in sorted(strategy_counts.items()):
    print(f"  {strategy:<12}: {count}")

# LLM Guard enrichment summary
print()
print("LLM Guard scan:")
llmguard_results = llmguard.scan_findings(findings[:5])  # sample first 5
flagged_input  = sum(1 for r in llmguard_results if not r['input_is_valid'])
flagged_output = sum(1 for r in llmguard_results if not r['output_is_valid'])
print(f"  Sample (first 5): {flagged_input} input flags, {flagged_output} output flags")

# NeMo config preview
nemo_path = Path('artifacts/nemo_guardrails.yaml')
if nemo_path.exists():
    content = nemo_path.read_text(encoding='utf-8')
    categories_line = [l for l in content.splitlines() if 'Based on' in l]
    if categories_line:
        print()
        print("NeMo config:", categories_line[0].strip('# '))

# Roundtrip check
print()
print("Roundtrip load check:")
loaded = RemediatorAgent.load_results(results_path)
assert len(loaded) == len(results), "FAIL: loaded count mismatch"
print(f"  Loaded {len(loaded)} results — OK")

# Findings coverage summary
llm_coverage = {}
for f in findings:
    llm_coverage[f.owasp_llm_category] = llm_coverage.get(f.owasp_llm_category, 0) + 1

print()
print("OWASP LLM coverage from findings fed to Agent 2:")
all_ok = True
for i in range(1, 11):
    code = f"LLM{i:02d}"
    count = llm_coverage.get(code, 0)
    mark = "YES" if count > 0 else "MISSING"
    if count == 0:
        all_ok = False
    print(f"  {code}: {mark} ({count})")

print()
if all_ok:
    print("ALL LLM01-LLM10 covered -- Agent 1 -> Agent 2 pipeline: PASS")
else:
    print("COVERAGE INCOMPLETE — see gaps above")
