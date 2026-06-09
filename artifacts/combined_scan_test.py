"""Agent 1 — full end-to-end smoke test: Garak + PyRIT + VectorPoisoner.

Run with:
    python artifacts/combined_scan_test.py

Requires:
    - A real Garak .report.jsonl file (path below)
    - pyrit installed  (pip install pyrit)
    - chromadb installed (pip install chromadb)

This script does NOT call any live LLM.  PyRIT uses a VulnerableModel stub
that returns canned compliant responses; VectorPoisoner uses an in-memory
Chroma store with an offline hash embedding function.
"""
import sys
sys.path.insert(0, 'src')
sys.path.insert(0, '.')

from pathlib import Path
from integration_bridge.parser import GarakParser
from tools.pyrit_runner import PyRITRunner, DEFAULT_PROBES
from tools.vector_poisoner import VectorPoisoner
from agents.scanner_agent import ScannerAgent


# ── Garak: replay real .report.jsonl produced by a previous run ──────────
garak_report = Path(r'C:\Users\T460S\.local\share\garak\garak_runs\garak.bd94483e-2ebc-453b-b3d2-86dd9053c5d7.report.jsonl')
garak_parser = GarakParser(garak_report)
garak_bridge_findings = garak_parser.parse()


class _FakeGarakRunner:
    def run_scan(self, probes=None):
        return garak_bridge_findings


# ── PyRIT: canned "vulnerable" target — responds as if it were compromised ─
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


# ── Run all three scanners ────────────────────────────────────────────────
pyrit_runner = PyRITRunner(target=VulnerableModel())
vector_poisoner = VectorPoisoner()  # real Chroma, offline hash embeddings

agent = ScannerAgent(
    garak_runner=_FakeGarakRunner(),   # 140 real Garak findings from JSONL
    pyrit_runner=pyrit_runner,          # 13 multi-turn PyRIT probes
    vector_poisoner=vector_poisoner,    # 5 LLM08 vector-store poisoning probes
)
findings = agent.scan()

# ── Coverage accounting ───────────────────────────────────────────────────
llm_coverage = {}
asi_coverage = {}
for f in findings:
    llm_coverage[f.owasp_llm_category] = llm_coverage.get(f.owasp_llm_category, 0) + 1
    for asi in f.owasp_agentic_categories:
        asi_coverage[asi] = asi_coverage.get(asi, 0) + 1

garak_count  = sum(1 for f in findings if f.source == "garak")
pyrit_count  = sum(1 for f in findings if f.source == "pyrit")
vector_count = sum(1 for f in findings if f.source == "vector")

# ── Print report ─────────────────────────────────────────────────────────
print("=== Agent 1 Scanner — Garak + PyRIT + VectorPoisoner ===")
print(f"Total findings: {len(findings)}  "
      f"({garak_count} Garak, {pyrit_count} PyRIT, {vector_count} Vector)")
print()

print("OWASP LLM Top 10 Coverage:")
for i in range(1, 11):
    code = f"LLM{i:02d}"
    count = llm_coverage.get(code, 0)
    mark = "YES" if count > 0 else "MISSING"
    print(f"  {code}: {mark} ({count} findings)")

print()
print("OWASP Agentic (ASI) Top 10 Coverage:")
ASI_NAMES = {
    'ASI01': 'Agent Goal Hijack',
    'ASI02': 'Tool Misuse & Exploitation',
    'ASI03': 'Identity & Privilege Abuse',
    'ASI04': 'Agentic Supply Chain',
    'ASI05': 'Unexpected Code Execution',
    'ASI06': 'Memory & Context Poisoning',
    'ASI07': 'Insecure Inter-Agent Communication',
    'ASI08': 'Cascading Failures',
    'ASI09': 'Human-Agent Trust Exploitation',
    'ASI10': 'Rogue Agents',
}
all_covered = True
for i in range(1, 11):
    code = f"ASI{i:02d}"
    count = asi_coverage.get(code, 0)
    name = ASI_NAMES[code]
    if count > 0:
        print(f"  {code} ({name}): COVERED ({count} findings)")
    else:
        print(f"  {code} ({name}): MISSING  <-- GAP")
        all_covered = False

print()
if all_covered:
    print("ALL 10 ASI CATEGORIES COVERED")
else:
    print("COVERAGE INCOMPLETE — see gaps above")

print()
print("Per-probe breakdown (Vector scanner):")
for f in findings:
    if f.source == "vector":
        status = "ATTACK SUCCEEDED" if f.is_successful_attack else "blocked"
        print(f"  {f.probe_name}: {status}")

out = agent.save_findings(findings, 'artifacts/combined_scan.json')
print()
print(f"findings saved: {out}")
