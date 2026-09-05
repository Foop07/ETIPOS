"""
ETIPOS Gateway Server (Node 2 Inspection Gatekeeper)
Local FastAPI / WebSocket engine orchestrating:
  - Ephemeral X25519 Session Handshakes
  - In-flight static APK & binary decompilation (FlowDroid / Androguard principles)
  - Local AI threat scoring (Ollama / CyberSecEval benchmark)
  - Ed25519 Cryptographic signing of inspection reports
  - Optical Air-Gap QR burst generator (Scaife et al. optical channel)
"""

import os
import sys
import time
import uuid
import json
import base64
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure path to protocols and gateway components
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from protocols.crypto_engine import CryptoEngine, PayloadChunker
from gateway_server.analyzer.static_analyzer import StaticAnalyzer
from gateway_server.analyzer.ai_evaluator import AIEvaluator
from gateway_server.airgap.optical_burst import OpticalBurstEngine

app = FastAPI(
    title="ETIPOS Gateway Server",
    description="Zero-Cloud Air-Gapped Security Gatekeeper & Cryptographic Relay",
    version="1.0.0"
)

# CORS middleware for local frontend connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gateway persistent state (in-memory for local session lifecycle)
GATEWAY_SIGNING_KEY, GATEWAY_VERIFY_KEY = CryptoEngine.generate_ed25519_keypair()
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}
INSPECTED_PAYLOADS: Dict[str, Dict[str, Any]] = {}
STORED_RAW_PAYLOADS: Dict[str, bytes] = {}


# Pydantic Schemas
class HandshakeRequest(BaseModel):
    session_id: Optional[str] = None
    sender_id: str
    client_ephemeral_public_key: str  # Base64 X25519


class HandshakeResponse(BaseModel):
    session_id: str
    gateway_ephemeral_public_key: str  # Base64 X25519
    gateway_signing_public_key: str     # Base64 Ed25519
    status: str


class ChunkUploadRequest(BaseModel):
    session_id: str
    payload_id: str
    chunk_index: int
    total_chunks: int
    nonce: str
    ciphertext: str
    auth_tag: str
    hmac_sha256: str


# -------------------------------------------------------------
# REST Endpoints
# -------------------------------------------------------------

@app.post("/api/handshake", response_model=HandshakeResponse)
def handle_handshake(req: HandshakeRequest):
    """Performs ephemeral X25519 key exchange with Node 1 (Sender)."""
    session_id = req.session_id or str(uuid.uuid4())
    
    # Generate Gateway ephemeral keypair for this session
    gw_priv, gw_pub = CryptoEngine.generate_x25519_keypair()
    client_pub = CryptoEngine.b64_to_public_key(req.client_ephemeral_public_key)
    
    # Derive shared session keys
    derived_keys = CryptoEngine.derive_session_keys(gw_priv, client_pub)
    
    ACTIVE_SESSIONS[session_id] = {
        "session_id": session_id,
        "sender_id": req.sender_id,
        "created_at": int(time.time()),
        "aes_key": derived_keys["aes_key"],
        "hmac_key": derived_keys["hmac_key"],
        "client_pub_b64": req.client_ephemeral_public_key,
        "chunks_buffer": {}
    }

    # Gateway public Ed25519 key for report verification on Node 3
    gw_verify_b64 = CryptoEngine.ed25519_public_key_to_b64(GATEWAY_VERIFY_KEY)

    return HandshakeResponse(
        session_id=session_id,
        gateway_ephemeral_public_key=CryptoEngine.public_key_to_b64(gw_pub),
        gateway_signing_public_key=gw_verify_b64,
        status="SESSION_ESTABLISHED"
    )


@app.post("/api/payload/chunk")
def upload_chunk(chunk: ChunkUploadRequest):
    """Receives and buffers an encrypted payload chunk from Node 1."""
    session = ACTIVE_SESSIONS.get(chunk.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    payload_id = chunk.payload_id
    if payload_id not in session["chunks_buffer"]:
        session["chunks_buffer"][payload_id] = []

    session["chunks_buffer"][payload_id].append(chunk.model_dump())

    return {
        "status": "CHUNK_RECEIVED",
        "payload_id": payload_id,
        "chunk_index": chunk.chunk_index,
        "buffered_count": len(session["chunks_buffer"][payload_id]),
        "total_chunks": chunk.total_chunks
    }


@app.post("/api/payload/inspect-direct")
async def inspect_direct_file(
    file: UploadFile = File(...),
    message_text: Optional[str] = Form(None)
):
    """
    Direct inspection endpoint (for testing / GUI upload / direct gateway ingest).
    Runs Static Analysis + AI CyberSecEval + Cryptographic Signing.
    """
    raw_bytes = await file.read()
    filename = file.filename or "payload.bin"
    payload_id = str(uuid.uuid4())

    return await _process_and_inspect_payload(payload_id, filename, raw_bytes, message_text)


@app.post("/api/payload/{payload_id}/assemble-and-inspect")
async def assemble_and_inspect(payload_id: str, session_id: str, filename: str = "payload.bin"):
    """
    Decrypts buffered frames from an active session, reassembles bytes, and runs security inspection.
    """
    session = ACTIVE_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    chunks = session["chunks_buffer"].get(payload_id)
    if not chunks:
        raise HTTPException(status_code=404, detail="No chunks buffered for this payload")

    try:
        decrypted_bytes = PayloadChunker.reassemble_payload(
            chunks, session["aes_key"], session["hmac_key"]
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption or integrity failed: {str(e)}")

    return await _process_and_inspect_payload(payload_id, filename, decrypted_bytes)


async def _process_and_inspect_payload(
    payload_id: str,
    filename: str,
    raw_bytes: bytes,
    preview_text: Optional[str] = None
) -> Dict[str, Any]:
    """Runs the complete Static + AI + Cryptographic inspection pipeline."""
    # 1. Static Analysis
    static_report = StaticAnalyzer.analyze_bytes(raw_bytes, filename=filename)

    # 2. Local AI CyberSecEval Threat Scoring
    snippet = preview_text or raw_bytes[:1000].decode('utf-8', errors='ignore')
    ai_report = await AIEvaluator.evaluate_payload(static_report, payload_preview=snippet)

    # 3. Composite Risk Calculation
    # Formula: 45% Static Threat Score + 35% Malware Intent + 20% Exfiltration/Injection
    composite = (
        static_report["static_threat_score"] * 0.45 +
        ai_report.get("malware_intent_score", 0.0) * 0.35 +
        max(ai_report.get("data_exfiltration_score", 0.0), ai_report.get("prompt_injection_score", 0.0)) * 0.20
    )
    composite = min(10.0, round(composite, 1))

    # Verdict policy
    if composite >= 7.0:
        verdict = "BLOCK"
    elif composite >= 3.5:
        verdict = "QUARANTINE"
    else:
        verdict = "PASS"

    # 4. Construct Final Inspection Report
    report = {
        "payload_id": payload_id,
        "filename": filename,
        "timestamp": int(time.time()),
        "sha256": static_report["sha256"],
        "size_bytes": len(raw_bytes),
        "static_analysis": static_report,
        "ai_analysis": ai_report,
        "composite_risk_score": composite,
        "verdict": verdict,
    }

    # 5. Ed25519 Digital Signature by Gateway
    sig = CryptoEngine.sign_audit_report(report, GATEWAY_SIGNING_KEY)
    report["gateway_signature"] = sig

    # Persist in gateway cache
    INSPECTED_PAYLOADS[payload_id] = report
    STORED_RAW_PAYLOADS[payload_id] = raw_bytes

    return report


@app.get("/api/payload/{payload_id}/report")
def get_report(payload_id: str):
    """Retrieves full inspection audit report."""
    report = INSPECTED_PAYLOADS.get(payload_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/api/payload/{payload_id}/optical_burst")
def get_optical_burst(payload_id: str, fps: int = 15):
    """
    Generates multi-frame QR burst stream for Scaife et al. optical air-gap transfer.
    """
    report = INSPECTED_PAYLOADS.get(payload_id)
    raw_bytes = STORED_RAW_PAYLOADS.get(payload_id)
    if not report or not raw_bytes:
        raise HTTPException(status_code=404, detail="Payload not found or not yet inspected")

    if report["verdict"] == "BLOCK":
        raise HTTPException(status_code=403, detail="Blocked malicious payload cannot be transmitted across air-gap!")

    frames = OpticalBurstEngine.generate_burst_frames(
        raw_bytes,
        payload_id=payload_id,
        gateway_signature=report["gateway_signature"]
    )

    # Render base64 QR codes for each frame
    rendered_frames = []
    for f in frames:
        rendered_frames.append({
            **f,
            "qr_image_data": OpticalBurstEngine.render_frame_qr_png_base64(f)
        })

    return {
        "payload_id": payload_id,
        "filename": report["filename"],
        "total_frames": len(frames),
        "fps": fps,
        "gateway_signature": report["gateway_signature"],
        "frames": rendered_frames
    }


@app.get("/api/stats")
def get_stats():
    """Returns gateway security statistics."""
    total = len(INSPECTED_PAYLOADS)
    passed = sum(1 for p in INSPECTED_PAYLOADS.values() if p["verdict"] == "PASS")
    quarantined = sum(1 for p in INSPECTED_PAYLOADS.values() if p["verdict"] == "QUARANTINE")
    blocked = sum(1 for p in INSPECTED_PAYLOADS.values() if p["verdict"] == "BLOCK")
    avg_score = (
        round(sum(p["composite_risk_score"] for p in INSPECTED_PAYLOADS.values()) / total, 1)
        if total > 0 else 0.0
    )

    return {
        "total_inspected": total,
        "passed": passed,
        "quarantined": quarantined,
        "blocked": blocked,
        "average_risk_score": avg_score,
        "active_sessions": len(ACTIVE_SESSIONS)
    }


@app.get("/api/sessions")
def get_sessions():
    """Lists active peer sessions."""
    return [
        {
            "session_id": s["session_id"],
            "sender_id": s["sender_id"],
            "created_at": s["created_at"],
            "buffered_payloads": list(s["chunks_buffer"].keys())
        }
        for s in ACTIVE_SESSIONS.values()
    ]


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serves the rich real-time Gateway Security Dashboard."""
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard", "index.html")
    if os.path.exists(dashboard_path):
        with open(dashboard_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>ETIPOS Gateway Server is Running</h1><p>Visit /docs for Swagger API.</p>"


if __name__ == "__main__":
    import uvicorn
    print("[*] Starting ETIPOS Gateway Server on http://0.0.0.0:8000 ...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
