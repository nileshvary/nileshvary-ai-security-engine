"""FastAPI bridge — exposes RemediAX Python data to the React (Bolt) dashboard.

Endpoints
---------
GET  /api/findings     → artifacts/findings.json (36 real scan findings)
GET  /api/guardrails   → guardrails.yaml parsed as JSON
GET  /api/score        → security score from calculate_security_score()
GET  /api/owasp        → OWASP LLM01-LLM10 + ASI01-ASI10 category metadata
GET  /api/pipeline     → 6-agent pipeline status summary
POST /api/assistant    → Claude AI chat via RemediAXAI._call()

Run:
    uvicorn api.main:app --port 8001 --reload
"""

from __future__ import annotations

import json
import logging
import os
import sys

logger = logging.getLogger(__name__)
import threading
import time
from pathlib import Path
from typing import Any

# Add project root to path so we can import components/
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="RemediAX API Bridge", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://remediax-ui.vercel.app",
        "*",  # allow all for local dev
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).parent.parent


def _read_findings() -> list[dict[str, Any]]:
    p = _ROOT / "artifacts" / "findings.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _read_guardrails() -> dict[str, Any]:
    p = _ROOT / "guardrails.yaml"
    if not p.exists():
        return {}
    try:
        import yaml  # PyYAML is already in requirements.txt
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _read_pipeline_summary() -> dict[str, Any]:
    p = _ROOT / "artifacts" / "pipeline_summary.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# GET /api/findings
# ---------------------------------------------------------------------------

@app.get("/api/findings")
def get_findings() -> list[dict[str, Any]]:
    """Return all scan findings from artifacts/findings.json.

    Each finding has: probe_name, owasp_llm_category, owasp_agentic_categories,
    severity, is_successful_attack, source, attack_prompt, model_response.
    """
    return _read_findings()


# ---------------------------------------------------------------------------
# GET /api/guardrails
# ---------------------------------------------------------------------------

@app.get("/api/guardrails")
def get_guardrails() -> dict[str, Any]:
    """Return parsed guardrails.yaml as JSON."""
    return _read_guardrails()


# ---------------------------------------------------------------------------
# GET /api/score
# ---------------------------------------------------------------------------

@app.get("/api/score")
def get_score() -> dict[str, Any]:
    """Return security posture score derived from current findings.

    Response: {score, label, color, finding_count, critical, high, medium, low}
    """
    findings = _read_findings()

    try:
        from components.security_score import calculate_security_score, score_status
        score = calculate_security_score(findings)
        label, color = score_status(score)
    except Exception:
        score, label, color = 0.0, "UNKNOWN", "#94A3B8"

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        if sev in counts:
            counts[sev] += 1

    return {
        "score": round(score, 1),
        "label": label,
        "color": color,
        "finding_count": len(findings),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
    }


# ---------------------------------------------------------------------------
# GET /api/owasp
# ---------------------------------------------------------------------------

@app.get("/api/owasp")
def get_owasp() -> dict[str, Any]:
    """Return OWASP LLM Top 10 + ASI Agentic Top 10 category metadata.

    Response: {
      llm: { LLM01: {name, color, icon, ...}, ... },
      asi: { ASI01: {name, color, icon, ...}, ... }
    }
    """
    try:
        from components.owasp_content import OWASP_CONTENT, ASI_CONTENT

        def _slim(d: dict[str, Any]) -> dict[str, Any]:
            return {
                k: {
                    "name": v.get("name", k),
                    "color": v.get("color", "#94A3B8"),
                    "icon": v.get("icon", "🔒"),
                    "danger_explanation": v.get("danger_explanation", ""),
                    "fix_explanation": v.get("fix_explanation", ""),
                }
                for k, v in d.items()
            }

        return {"llm": _slim(OWASP_CONTENT), "asi": _slim(ASI_CONTENT)}
    except Exception:
        return {"llm": {}, "asi": {}}


# ---------------------------------------------------------------------------
# GET /api/pipeline
# ---------------------------------------------------------------------------

@app.get("/api/pipeline")
def get_pipeline() -> dict[str, Any]:
    """Return 6-agent pipeline status + latest run summary.

    Combines pipeline_summary.json (if it exists) with agent metadata
    so the AgentPipeline component can show live status.
    """
    summary = _read_pipeline_summary()
    findings = _read_findings()
    guardrails = _read_guardrails()

    llm_cats = sorted({f.get("owasp_llm_category", "") for f in findings if f.get("owasp_llm_category")})
    asi_cats = sorted({a for f in findings for a in f.get("owasp_agentic_categories", [])})

    agents = [
        {
            "id": 1,
            "name": "Scanner",
            "tools": ["Garak", "PyRIT"],
            "color": "#06B6D4",
            "status": "completed" if findings else "idle",
            "findings": len(findings),
            "description": "Discovers LLM vulnerabilities — OWASP LLM01-LLM10 + ASI Agentic Top 10",
        },
        {
            "id": 2,
            "name": "Remediator",
            "tools": ["LLM Guard", "NeMo"],
            "color": "#F97316",
            "status": "completed" if summary.get("remediation_count", 0) > 0 else "idle",
            "remediations": summary.get("remediation_count", 0),
            "description": "Generates prompt patches, sanitization rules, and guardrail YAML",
        },
        {
            "id": 3,
            "name": "Reporter",
            "tools": ["Claude API", "Jinja2"],
            "color": "#3B82F6",
            "status": "completed" if (summary.get("artifacts", {}) or {}).get("html_report") else "idle",
            "description": "Produces 8-section HTML security report with per-finding cards",
        },
        {
            "id": 4,
            "name": "Verifier",
            "tools": ["Promptfoo"],
            "color": "#10B981",
            "status": "completed" if summary.get("verified_count", 0) > 0 else "idle",
            "verified": summary.get("verified_count", 0),
            "improvement": summary.get("overall_improvement_percent", 0),
            "description": "Measures before/after improvement and provides CI gate",
        },
        {
            "id": 5,
            "name": "Orchestrator",
            "tools": ["Claude API"],
            "color": "#8B5CF6",
            "status": "completed" if summary else "idle",
            "ci_passed": summary.get("ci_passed", False),
            "description": "Central coordinator — runs all 4 agents in sequence, saves artifacts",
        },
        {
            "id": 6,
            "name": "CVE Watcher",
            "tools": ["NVD API", "MITRE ATLAS", "OWASP"],
            "color": "#EF4444",
            "status": "active",
            "description": "Nightly auto-update engine — fetches new CVEs, maps to OWASP, generates probes",
        },
    ]

    return {
        "agents": agents,
        "summary": {
            "finding_count": len(findings),
            "owasp_llm_covered": llm_cats,
            "asi_covered": asi_cats,
            "guardrails_active": len(guardrails.get("input_guardrails", [])) + len(guardrails.get("output_guardrails", [])),
            "ci_passed": summary.get("ci_passed", False),
            "improvement_percent": summary.get("overall_improvement_percent", 0),
        },
    }


# ---------------------------------------------------------------------------
# GET /api/cve
# ---------------------------------------------------------------------------

@app.get("/api/cve")
def get_cve() -> dict[str, Any]:
    """Return CVE database stats from database_reports/cve_database.json."""
    p = _ROOT / "database_reports" / "cve_database.json"
    if not p.exists():
        return {"cves": [], "total": 0, "last_updated": None}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        cves = data if isinstance(data, list) else data.get("cves", [])
        return {
            "cves": cves[:20],  # return latest 20 for the UI
            "total": len(cves),
            "last_updated": cves[0].get("published") if cves else None,
        }
    except Exception:
        return {"cves": [], "total": 0, "last_updated": None}


# ---------------------------------------------------------------------------
# POST /api/assistant
# ---------------------------------------------------------------------------

class AssistantRequest(BaseModel):
    message: str


@app.post("/api/assistant")
def post_assistant(req: AssistantRequest) -> dict[str, str]:
    """Send a message to the Claude AI assistant.

    Requires ANTHROPIC_API_KEY environment variable.
    Falls back to a rule-based reply if the key is not set.
    """
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message is required")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if api_key:
        try:
            from components.ai_client import RemediAXAI
            ai = RemediAXAI(api_key=api_key)
            findings = _read_findings()
            context = ""
            if findings:
                cats = sorted({f.get("owasp_llm_category", "") for f in findings if f.get("owasp_llm_category")})
                context = (
                    f"\n\nCurrent scan context: {len(findings)} findings found, "
                    f"covering OWASP categories: {', '.join(cats)}."
                )
            prompt = (
                "You are the RemediAX AI Security Assistant. You help security engineers "
                "understand LLM vulnerabilities, OWASP LLM Top 10, ASI Agentic Top 10, "
                "and how to fix them using RemediAX agents."
                f"{context}\n\nUser question: {req.message}"
            )
            reply = ai._call(prompt, max_tokens=400)
            if reply:
                return {"reply": reply}
        except Exception:
            pass

    # Rule-based fallback
    msg = req.message.lower()
    findings = _read_findings()
    if any(w in msg for w in ["score", "posture", "safe", "secure"]):
        try:
            from components.security_score import calculate_security_score, score_status
            score = calculate_security_score(findings)
            label, _ = score_status(score)
            return {"reply": f"Current security posture score is {score:.0f}/100 — status: {label}. Run a fresh scan to update."}
        except Exception:
            pass
    if any(w in msg for w in ["finding", "threat", "vuln", "attack"]):
        cats = sorted({f.get("owasp_llm_category", "") for f in findings if f.get("owasp_llm_category")})
        return {"reply": f"Found {len(findings)} vulnerabilities across {len(cats)} OWASP LLM categories: {', '.join(cats)}. Most critical: {findings[0].get('owasp_llm_category', 'N/A') if findings else 'none'}."}
    if any(w in msg for w in ["guardrail", "fix", "patch", "remediat"]):
        g = _read_guardrails()
        n = len(g.get("input_guardrails", [])) + len(g.get("output_guardrails", []))
        return {"reply": f"RemediAX has generated {n} active guardrail rules covering {len(g.get('covered_owasp_categories', []))} OWASP LLM categories. Check guardrails.yaml for the full config."}
    if any(w in msg for w in ["agent", "pipeline", "workflow"]):
        return {"reply": "RemediAX uses 6 agents: Scanner (Garak+PyRIT) → Remediator (LLM Guard+NeMo) → Reporter (Claude+Jinja2) → Verifier (Promptfoo) → Orchestrator (Claude API Brain) → CVE Watcher (NVD API, nightly). Set ANTHROPIC_API_KEY for full AI responses."}
    if any(w in msg for w in ["cve", "nvd", "update", "latest"]):
        return {"reply": "Agent 6 (CVE Watcher) monitors NVD API, MITRE ATLAS, and OWASP nightly. It auto-maps new CVEs to OWASP LLM categories and generates PyRIT probes. Set ANTHROPIC_API_KEY for full AI responses."}

    return {"reply": "I'm the RemediAX AI Security Assistant. Set ANTHROPIC_API_KEY in your environment to unlock full Claude-powered responses. I can help with OWASP LLM Top 10, ASI Agentic Top 10, scan results, and remediation guidance."}


# ---------------------------------------------------------------------------
# GET /api/config  +  POST /api/config
# ---------------------------------------------------------------------------

_CONFIG_FILE = _ROOT / "config.json"
_ENV_FILE = _ROOT / ".env"

_CONFIG_DEFAULTS: dict[str, Any] = {
    "target_url": "",
    "system_prompt": "",
    "scanners": ["garak", "pyrit", "vector"],
    "pyrit_max_turns": 5,
    "output_dir": "artifacts/",
    "log_level": "INFO",
}

_API_KEY_FIELDS = {"anthropic_api_key", "openai_api_key", "mistral_api_key"}


def _read_config() -> dict[str, Any]:
    cfg = dict(_CONFIG_DEFAULTS)
    if _CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(_CONFIG_FILE.read_text(encoding="utf-8")))
        except Exception:
            pass
    # Report which API keys are set (from env), never return the values
    cfg["anthropic_api_key_set"] = bool(os.environ.get("ANTHROPIC_API_KEY"))
    cfg["openai_api_key_set"] = bool(os.environ.get("OPENAI_API_KEY"))
    cfg["mistral_api_key_set"] = bool(os.environ.get("MISTRAL_API_KEY"))
    # Report which custom keys are set
    cfg["custom_key_names"] = cfg.get("custom_key_names", [])
    cfg["custom_keys_set"] = {k: bool(os.environ.get(k)) for k in cfg["custom_key_names"]}
    return cfg


def _write_env_key(key_name: str, value: str) -> None:
    """Append or update KEY=value in .env file. Empty value removes the key."""
    env_key = key_name.upper()
    lines: list[str] = []
    if _ENV_FILE.exists():
        lines = _ENV_FILE.read_text(encoding="utf-8").splitlines()
    if value == "":
        # Delete the key
        lines = [l for l in lines if not l.startswith(f"{env_key}=")]
        os.environ.pop(env_key, None)
    else:
        found = False
        for i, line in enumerate(lines):
            if line.startswith(f"{env_key}="):
                lines[i] = f"{env_key}={value}"
                found = True
                break
        if not found:
            lines.append(f"{env_key}={value}")
        os.environ[env_key] = value
    _ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


class ConfigPayload(BaseModel):
    target_url: str | None = None
    system_prompt: str | None = None
    scanners: list[str] | None = None
    pyrit_max_turns: int | None = None
    output_dir: str | None = None
    log_level: str | None = None
    # API keys — written to .env, never stored in config.json
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    mistral_api_key: str | None = None
    # Custom API keys — dict of { KEY_NAME: value }, all written to .env
    custom_keys: dict[str, str] | None = None


@app.get("/api/config")
def get_config() -> dict[str, Any]:
    """Return current config. API key values are never returned — only whether they are set."""
    return _read_config()


@app.post("/api/config")
def post_config(payload: ConfigPayload) -> dict[str, Any]:
    """Save config fields to config.json; API keys go to .env only."""
    cfg = _read_config()
    # Remove sentinel fields before saving to JSON
    for sentinel in ("anthropic_api_key_set", "openai_api_key_set", "mistral_api_key_set"):
        cfg.pop(sentinel, None)

    data = payload.model_dump(exclude_none=True)

    # Handle fixed API keys — write to .env
    for key_field in _API_KEY_FIELDS:
        if key_field in data:
            _write_env_key(key_field, data.pop(key_field))

    # Handle custom API keys — write each to .env, store names in config.json
    custom_keys: dict[str, str] = data.pop("custom_keys", None) or {}
    custom_key_names: list[str] = []
    for key_name, key_value in custom_keys.items():
        if key_name.strip():
            _write_env_key(key_name.strip(), key_value)
            custom_key_names.append(key_name.strip().upper())
    if custom_key_names:
        existing = cfg.get("custom_key_names", [])
        merged = list(dict.fromkeys(existing + custom_key_names))
        data["custom_key_names"] = merged

    # Merge remaining fields into config.json
    cfg.update(data)
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")

    return {"status": "saved", **_read_config()}


# ── Scan state ────────────────────────────────────────────────────────────────

_scan_state: dict[str, Any] = {
    "running": False,
    "phase": "idle",       # idle | initializing | garak | pyrit | vector | saving | done | error
    "progress": 0,         # 0–100
    "findings_count": 0,
    "severity_counts": {},
    "started_at": None,
    "finished_at": None,
    "error": None,
}
_scan_lock = threading.Lock()


class _GarakAdapter:
    """Bridge between scanner_agent's run_scan(probes=...) and GarakRunner.run_scan(command).

    scanner_agent.py calls self._garak.run_scan(probes=list) but GarakRunner.run_scan()
    requires run_scan(command: list[str]).  This adapter translates the call so no
    agent files need to be touched.
    """

    def __init__(self, runner: Any, target_url: str = "") -> None:
        self._r = runner
        self._url = target_url

    def run_scan(self, probes: list[str] | None = None) -> list[Any]:  # type: ignore[override]
        cmd = self._r.build_command(
            target_type="rest.RestGenerator",
            target_name="",
            probes=probes,
        )
        if self._url:
            cmd.extend(["--uri", self._url])
        # Consume subprocess output (we don't need streaming here)
        try:
            list(self._r.run_scan(cmd))
        except Exception as exc:
            logger.warning("_GarakAdapter.run_scan subprocess error: %s", exc)
            return []
        report = self._r.get_latest_report()
        return self._r.parse_report(report) if report else []


def _run_scan_thread(scanners: list[str], pyrit_max_turns: int, target_url: str = "", api_key: str = "") -> None:
    """Background thread: runs ScannerAgent and updates _scan_state."""
    global _scan_state
    try:
        with _scan_lock:
            _scan_state.update({"phase": "initializing", "progress": 5, "error": None})

        # Build HTTP target when a URL is configured
        http_target = None
        if target_url:
            try:
                from tools.http_target import HttpTarget
                http_target = HttpTarget(url=target_url, api_key=api_key)
                logger.info("HttpTarget created for %s", target_url)
            except Exception as exc:
                logger.warning("HttpTarget import failed: %s", exc)

        # Lazy imports — only import runners that are enabled
        garak_runner = None
        pyrit_runner = None
        vector_poisoner = None

        if "garak" in scanners:
            try:
                from tools.garak_runner import GarakRunner
                garak_runner = _GarakAdapter(GarakRunner(), target_url=target_url)
            except Exception as e:
                pass  # Garak unavailable — skip

        if "pyrit" in scanners:
            try:
                from tools.pyrit_runner import PyRITRunner
                pyrit_runner = PyRITRunner(target=http_target)
            except Exception as e:
                pass

        if "vector" in scanners:
            try:
                from tools.vector_poisoner import VectorPoisoner
                vector_poisoner = VectorPoisoner()
            except Exception as e:
                pass

        from agents.scanner_agent import ScannerAgent
        agent = ScannerAgent(
            garak_runner=garak_runner,
            pyrit_runner=pyrit_runner,
            vector_poisoner=vector_poisoner,
        )

        # Phase: garak
        if garak_runner is not None:
            with _scan_lock:
                _scan_state.update({"phase": "garak", "progress": 20})

        # Phase: pyrit
        if pyrit_runner is not None:
            with _scan_lock:
                _scan_state.update({"phase": "pyrit", "progress": 60})

        # Phase: vector
        if vector_poisoner is not None:
            with _scan_lock:
                _scan_state.update({"phase": "vector", "progress": 80})

        with _scan_lock:
            _scan_state.update({"phase": "running", "progress": 85})

        findings = agent.scan(pyrit_max_turns=pyrit_max_turns)

        with _scan_lock:
            _scan_state.update({"phase": "saving", "progress": 98})

        artifacts_dir = _ROOT / "artifacts"
        artifacts_dir.mkdir(exist_ok=True)
        agent.save_findings(findings, artifacts_dir / "findings.json")

        # Count severities
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = (f.severity or "LOW").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Auto-generate report (Agent 3) so Reports tab is always current
        with _scan_lock:
            _scan_state.update({"phase": "reporting", "progress": 99})
        try:
            from agents.reporter_agent import ReporterAgent
            from schemas.finding import Finding

            # Load remediation results if available (Agent 2 output)
            remediation_results: list = []
            rem_path = artifacts_dir / "remediation_results.json"
            if rem_path.exists():
                try:
                    from agents.remediator_agent import RemediatorAgent
                    rem_raw = json.loads(rem_path.read_text(encoding="utf-8"))
                    remediation_results = rem_raw
                except Exception:
                    remediation_results = []

            reporter = ReporterAgent()
            html = reporter.generate_report(
                findings=findings,
                results=remediation_results,
                target=target_url or "LLM Target",
            )
            reporter.save_report(html, artifacts_dir / "summary.html")
            logger.info("Report auto-generated at artifacts/summary.html")
        except Exception as rep_exc:
            logger.warning("Auto-report generation failed (non-fatal): %s", rep_exc)

        with _scan_lock:
            _scan_state.update({
                "running": False,
                "phase": "done",
                "progress": 100,
                "findings_count": len(findings),
                "severity_counts": sev_counts,
                "finished_at": time.time(),
                "error": None,
            })

    except Exception as exc:
        with _scan_lock:
            _scan_state.update({
                "running": False,
                "phase": "error",
                "progress": 0,
                "error": str(exc),
                "finished_at": time.time(),
            })


@app.post("/api/scan/start")
def start_scan() -> dict[str, Any]:
    """Start Agent 1 (Scanner) in a background thread."""
    with _scan_lock:
        if _scan_state["running"]:
            raise HTTPException(status_code=409, detail="Scan already running")
        _scan_state.update({
            "running": True,
            "phase": "initializing",
            "progress": 0,
            "findings_count": 0,
            "severity_counts": {},
            "started_at": time.time(),
            "finished_at": None,
            "error": None,
        })

    cfg = _read_config()
    scanners: list[str] = cfg.get("scanners", ["garak", "pyrit", "vector"])
    pyrit_max_turns: int = int(cfg.get("pyrit_max_turns", 5))
    target_url: str = cfg.get("target_url", "")
    api_key: str = (
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("MISTRAL_API_KEY")
        or ""
    )

    t = threading.Thread(target=_run_scan_thread, args=(scanners, pyrit_max_turns, target_url, api_key), daemon=True)
    t.start()
    return {"status": "started"}


@app.get("/api/scan/status")
def get_scan_status() -> dict[str, Any]:
    """Return current scan state."""
    with _scan_lock:
        return dict(_scan_state)


@app.post("/api/scan/reset")
def reset_scan() -> dict[str, Any]:
    """Reset scan state to idle so a new scan can start."""
    with _scan_lock:
        if _scan_state["running"]:
            raise HTTPException(status_code=409, detail="Cannot reset while scan is running")
        _scan_state.update({
            "running": False,
            "phase": "idle",
            "progress": 0,
            "findings_count": 0,
            "severity_counts": {},
            "started_at": None,
            "finished_at": None,
            "error": None,
        })
    return {"status": "reset"}


# ---------------------------------------------------------------------------
# Remediation results + guardrail apply
# ---------------------------------------------------------------------------

REMEDIATION_FILE = _ROOT / "artifacts" / "remediation_results.json"


@app.get("/api/remediation_results")
def get_remediation_results() -> list[dict[str, Any]]:
    """Return all remediation results from artifacts/remediation_results.json."""
    if not REMEDIATION_FILE.exists():
        return []
    return json.loads(REMEDIATION_FILE.read_text(encoding="utf-8"))


class ApplyPayload(BaseModel):
    indices: list[int]


@app.post("/api/guardrails/apply")
def apply_guardrails(payload: ApplyPayload) -> dict[str, Any]:
    """Merge approved remediation patches into guardrails.yaml."""
    import yaml  # already available via nemoguardrails dep

    if not REMEDIATION_FILE.exists():
        raise HTTPException(status_code=404, detail="remediation_results.json not found")

    results: list[dict] = json.loads(REMEDIATION_FILE.read_text(encoding="utf-8"))

    guardrails_path = _ROOT / "guardrails.yaml"
    existing: dict = yaml.safe_load(guardrails_path.read_text(encoding="utf-8")) or {}
    input_rules: list = existing.get("input_guardrails", [])
    output_rules: list = existing.get("output_guardrails", [])

    existing_ids: set[str] = {r.get("id", "") for r in input_rules + output_rules}
    applied = 0

    for idx in payload.indices:
        if idx < 0 or idx >= len(results):
            continue
        result = results[idx]
        gc = result.get("guardrail_config")
        if not gc:
            continue
        for rule in gc.get("input_filters", []):
            rule_id = rule.get("id", f"auto-input-{idx}")
            if rule_id not in existing_ids:
                input_rules.append(rule)
                existing_ids.add(rule_id)
                applied += 1
        for rule in gc.get("output_filters", []):
            rule_id = rule.get("id", f"auto-output-{idx}")
            if rule_id not in existing_ids:
                output_rules.append(rule)
                existing_ids.add(rule_id)
                applied += 1

    existing["input_guardrails"] = input_rules
    existing["output_guardrails"] = output_rules
    guardrails_path.write_text(yaml.dump(existing, default_flow_style=False, allow_unicode=True), encoding="utf-8")

    return {
        "applied": applied,
        "guardrails_total": len(input_rules) + len(output_rules),
    }


# ---------------------------------------------------------------------------
# GET /api/report
# ---------------------------------------------------------------------------

@app.post("/api/report/generate")
def generate_report() -> dict[str, Any]:
    """Re-run Agent 3 (ReporterAgent) against current findings.json → summary.html."""
    findings_path = _ROOT / "artifacts" / "findings.json"
    if not findings_path.exists():
        raise HTTPException(status_code=404, detail="findings.json not found — run a scan first")
    try:
        from schemas.finding import Finding
        from agents.reporter_agent import ReporterAgent

        findings_raw = json.loads(findings_path.read_text(encoding="utf-8"))
        findings = [Finding.from_dict(f) for f in findings_raw]

        # Load remediation results if available
        results: list = []
        rem_path = _ROOT / "artifacts" / "remediation_results.json"
        if rem_path.exists():
            try:
                results = json.loads(rem_path.read_text(encoding="utf-8"))
            except Exception:
                results = []

        cfg = _read_config()
        target = cfg.get("target_url") or "LLM Target"

        reporter = ReporterAgent()
        html = reporter.generate_report(findings=findings, results=results, target=target)
        out = _ROOT / "artifacts" / "summary.html"
        reporter.save_report(html, out)
        return {"status": "ok", "findings": len(findings), "size_bytes": len(html)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/report/exists")
def get_report_exists() -> dict[str, Any]:
    """Return whether artifacts/summary.html exists."""
    p = _ROOT / "artifacts" / "summary.html"
    return {"exists": p.exists(), "size_kb": round(p.stat().st_size / 1024, 1) if p.exists() else 0}


@app.get("/api/report", response_class=HTMLResponse)
def get_report() -> HTMLResponse:
    """Serve artifacts/summary.html as HTML (Agent 3 output)."""
    p = _ROOT / "artifacts" / "summary.html"
    if not p.exists():
        raise HTTPException(status_code=404, detail="summary.html not found — run Agent 3 first")
    return HTMLResponse(content=p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "RemediAX API Bridge"}
