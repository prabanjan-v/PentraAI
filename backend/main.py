"""
main.py — PentraAI FastAPI Server
Handles scan requests and streams findings to the React frontend
via Server-Sent Events (SSE) in real time.

Endpoints:
  POST /scan        → Start a scan, returns scan_id
  GET  /scan/{id}   → SSE stream of live findings
  GET  /health      → Health check
"""

import json
import asyncio
import uuid
from datetime import datetime
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl

from config import settings
from agents.recon import run_recon

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-Driven Autonomous Web Penetration Testing Agent"
)

# ── CORS — allow React frontend to call this API ──────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory scan store (replace with DB in production) ─────────
# Maps scan_id → {"status": ..., "events": [...], "results": {...}}
_scans: dict[str, dict] = {}


# ── Request / Response models ─────────────────────────────────────

class ScanRequest(BaseModel):
    target_url: str                   # Target URL to scan
    # Credentials are optional — agent creates accounts automatically
    # Only provide these if auto account creation fails
    user_a_email: str = ""
    user_a_password: str = ""
    user_b_email: str = ""
    user_b_password: str = ""
    modules: list[str] = ["idor", "broken_auth", "business_logic"]

class ScanResponse(BaseModel):
    scan_id: str
    message: str
    stream_url: str


# ── Endpoints ──────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Quick health check — confirms the server is running."""
    return {
        "status": "ok",
        "app":    settings.app_name,
        "version": settings.app_version,
        "time":   datetime.utcnow().isoformat()
    }


@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """
    Start a new scan. Returns a scan_id immediately.
    The actual scan runs in the background.
    Connect to /scan/{scan_id}/stream to receive live results.
    """
    scan_id = str(uuid.uuid4())

    # Strip trailing slash to prevent double-slash in URLs
    request.target_url = request.target_url.rstrip("/")

    # Initialise scan record
    _scans[scan_id] = {
        "status":     "running",
        "target_url": request.target_url,
        "events":     [],
        "results":    {},
        "created_at": datetime.utcnow().isoformat(),
    }

    # Start scan in background (non-blocking)
    asyncio.create_task(
        _run_scan_pipeline(scan_id, request)
    )

    return ScanResponse(
        scan_id=scan_id,
        message="Scan started. Connect to stream_url for live results.",
        stream_url=f"/scan/{scan_id}/stream"
    )


@app.get("/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    """
    SSE endpoint — streams scan findings to the React frontend.
    The browser connects here and receives events as they happen.

    Event format:
      data: {"type": "progress", "message": "Recon started..."}
      data: {"type": "finding",  "module": "idor", "severity": "critical", ...}
      data: {"type": "complete", "summary": {...}}
    """
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    return StreamingResponse(
        _event_generator(scan_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        }
    )


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get the current state and results of a scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scans[scan_id]


# ── Internal helpers ──────────────────────────────────────────────

def _emit(scan_id: str, event_type: str, data: dict):
    """
    Add an event to the scan's event queue.
    The SSE stream picks this up and sends it to the browser.
    """
    event = {"type": event_type, **data}
    _scans[scan_id]["events"].append(event)


async def _event_generator(scan_id: str) -> AsyncGenerator[str, None]:
    """
    Async generator that yields SSE-formatted events.
    Polls the scan's event queue and sends new events to the client.
    """
    sent_count = 0

    while True:
        scan = _scans.get(scan_id)
        if not scan:
            break

        events = scan["events"]

        # Send any new events
        while sent_count < len(events):
            event = events[sent_count]
            yield f"data: {json.dumps(event)}\n\n"
            sent_count += 1

        # If scan is done, send final event and close
        if scan["status"] in ["complete", "error"]:
            if sent_count >= len(events):
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break

        await asyncio.sleep(0.3)   # Poll every 300ms


async def _run_scan_pipeline(scan_id: str, request: ScanRequest):
    """
    The main scan pipeline. Runs all phases sequentially.
    Emits events at each step so the frontend stays updated.
    """
    try:
        # ── Phase 1: Recon ────────────────────────────────────────
        _emit(scan_id, "progress", {
            "phase":   "recon",
            "message": f"Starting reconnaissance on {request.target_url}..."
        })

        recon_data = await run_recon(request.target_url)

        _emit(scan_id, "progress", {
            "phase":   "recon",
            "message": (
                f"Recon complete. Found {len(recon_data['alive_endpoints'])} endpoints, "
                f"{len(recon_data['id_patterns'])} ID patterns."
            ),
            "data": {
                "endpoints_found": len(recon_data["alive_endpoints"]),
                "id_patterns":     len(recon_data["id_patterns"]),
                "tech_stack":      recon_data["tech_stack"],
            }
        })

        # ── Phase 2: Hypothesis (LLM) ─────────────────────────────
        _emit(scan_id, "progress", {
            "phase":   "hypothesis",
            "message": "AI is analysing recon data to decide what to test..."
        })

        # Import here to avoid circular imports
        from agents.hypothesis import run_hypothesis
        test_plan = await run_hypothesis(recon_data)

        # Always include every module the user explicitly requested.
        # The LLM hypothesis prioritises but must never exclude user requests.
        hypothesis_modules = {item["module"].lower() for item in test_plan}
        for requested_module in request.modules:
            if requested_module.lower() not in hypothesis_modules:
                test_plan.append({
                    "module":     requested_module.lower(),
                    "priority":   99,
                    "reason":     "Explicitly requested by user",
                    "endpoints":  [request.target_url],
                    "confidence": "MEDIUM"
                })

        _emit(scan_id, "progress", {
            "phase":   "hypothesis",
            "message": f"AI test plan ready. Running {len(test_plan)} module(s).",
            "data":    {"test_plan": test_plan}
        })

        # ── Phase 3: Test modules ─────────────────────────────────
        all_findings = []

        for module_plan in test_plan:
            module_name = module_plan["module"].lower()

            _emit(scan_id, "progress", {
                "phase":   "testing",
                "message": f"Running {module_name.upper()} tests...",
                "data":    {"module": module_name, "reason": module_plan.get("reason", "")}
            })

            findings = await _run_module(
                module_name, module_plan, recon_data, request
            )

            # Emit each finding immediately as it is discovered
            for finding in findings:
                all_findings.append(finding)
                _emit(scan_id, "finding", finding)

            _emit(scan_id, "progress", {
                "phase":   "testing",
                "message": f"{module_name.upper()} complete — {len(findings)} finding(s).",
            })

        # ── Phase 4 & 5: Analysis + Report (LLM) ─────────────────
        _emit(scan_id, "progress", {
            "phase":   "report",
            "message": "AI is generating the final report..."
        })

        from agents.report import generate_report
        report = await generate_report(all_findings, recon_data)

        _scans[scan_id]["results"] = report
        _scans[scan_id]["status"]  = "complete"

        _emit(scan_id, "complete", {
            "message": "Scan complete.",
            "summary": {
                "total_findings": len(all_findings),
                "critical":       sum(1 for f in all_findings if f.get("severity") == "critical"),
                "high":           sum(1 for f in all_findings if f.get("severity") == "high"),
                "medium":         sum(1 for f in all_findings if f.get("severity") == "medium"),
            }
        })

    except Exception as e:
        _scans[scan_id]["status"] = "error"
        _emit(scan_id, "error", {"message": str(e)})


async def _run_module(
    module_name: str,
    module_plan: dict,
    recon_data: dict,
    request: ScanRequest
) -> list[dict]:
    """Route to the correct vulnerability module."""

    if module_name == "idor":
            from modules.idor import run_idor
            return await run_idor(
                recon_data       = recon_data,
                target_url       = request.target_url,
                user_a_email     = request.user_a_email,
                user_a_password  = request.user_a_password,
                user_b_email     = request.user_b_email,
                user_b_password  = request.user_b_password,
            )

    elif module_name == "broken_auth":
        from modules.broken_auth import run_broken_auth
        return await run_broken_auth(
            recon_data=recon_data,
            user_email=request.user_a_email,
            user_password=request.user_a_password,
            target_url=request.target_url,
        )

    elif module_name in ["business_logic", "race_condition"]:
        from modules.race_condition import run_race_condition
        return await run_race_condition(
            recon_data    = recon_data,
            target_url    = request.target_url,
            user_email    = request.user_a_email,
            user_password = request.user_a_password,
        )

    return []
