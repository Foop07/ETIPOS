import asyncio
import io
import json
import os
import time
import secrets
from typing import Dict, Any
import qrcode
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import Response, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import analyzer
import cert_manager

app = FastAPI(
    title="Secure Local Wireless Relay (ETIPOS)",
    description="Multi-Tier Local Malware Triage & Ephemeral Relay Gateway",
    version="1.0.0"
)

# Enable CORS for local network access (phones on Wi-Fi)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auto-ensure ClamAV is running on startup
@app.on_event("startup")
def on_startup():
    analyzer.ensure_clamd_running()

# Ephemeral file vault: stores approved files in memory temporarily
# Key: 6-digit PIN, Value: {filename, content_type, data, created_at, triage_report}
VAULT: Dict[str, Dict[str, Any]] = {}
EXPIRATION_SECONDS = 300  # Files expire in 5 minutes if not downloaded

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

def cleanup_expired_vault_entries():
    """Removes files that have exceeded the time-to-live."""
    now = time.time()
    expired_pins = [pin for pin, item in VAULT.items() if now - item["created_at"] > EXPIRATION_SECONDS]
    for pin in expired_pins:
        del VAULT[pin]

def generate_qr_bytes(content: str) -> bytes:
    """Generates PNG bytes for a QR code."""
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

@app.get("/")
def serve_portal():
    """Serves the mobile-responsive web portal."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Portal interface ready at /static/index.html"}

@app.get("/network-info")
def network_info():
    """Returns the local LAN IP and Wi-Fi connection URLs for phones."""
    local_ip = cert_manager.get_local_ip()
    return {
        "local_ip": local_ip,
        "port": 8000,
        "https_url": f"https://{local_ip}:8000",
        "http_url": f"http://{local_ip}:8000"
    }

@app.get("/qr-portal")
def portal_qr():
    """Generates a QR code for phone cameras to immediately open the portal."""
    local_ip = cert_manager.get_local_ip()
    target_url = f"https://{local_ip}:8000"
    png_bytes = generate_qr_bytes(target_url)
    return Response(content=png_bytes, media_type="image/png")

@app.get("/qr/{pin}")
def pin_qr(pin: str):
    """Generates a QR code image that directly opens the receiver tab on Phone B."""
    local_ip = cert_manager.get_local_ip()
    target_url = f"https://{local_ip}:8000/?pin={pin}"
    png_bytes = generate_qr_bytes(target_url)
    return Response(content=png_bytes, media_type="image/png")

@app.get("/health")
def health_check():
    """Returns operational status across all inspection tiers."""
    clam_client = analyzer.get_clamd_client()
    clam_status = "ONLINE" if clam_client else "OFFLINE"

    ollama_status = "OFFLINE"
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1.5) as r:
            if r.status == 200:
                ollama_status = "ONLINE"
    except Exception:
        pass

    return {
        "status": "HEALTHY",
        "components": {
            "tier1_magika": "ONLINE",
            "tier2_clamav": clam_status,
            "tier3_ollama_qwen": ollama_status
        },
        "vault_active_transfers": len(VAULT)
    }

@app.post("/scan")
async def scan_only(file: UploadFile = File(...)):
    """Dry-run file scan without storing or transferring."""
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    report = analyzer.run_full_triage(contents, file.filename or "unknown")
    return {
        "filename": file.filename,
        "size_bytes": len(contents),
        "triage": report
    }

def store_in_vault(contents: bytes, filename: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stores an approved payload in the ephemeral vault and returns the
    credential payload the client needs to receive it.
    """
    # Cryptographically random 6-digit PIN
    pin = f"{secrets.randbelow(900000) + 100000}"

    VAULT[pin] = {
        "filename": filename,
        "content_type": report.get("file_info", {}).get("mime_type") or "application/octet-stream",
        "data": contents,
        "created_at": time.time(),
        "triage_report": report
    }

    local_ip = cert_manager.get_local_ip()

    return {
        "status": "APPROVED",
        "pin": pin,
        "qr_url": f"/qr/{pin}",
        "receiver_url": f"https://{local_ip}:8000/?pin={pin}",
        "expires_in_seconds": EXPIRATION_SECONDS,
        "filename": filename,
        "size_bytes": len(contents),
        "triage": report
    }


def rejection_detail(report: Dict[str, Any]) -> Dict[str, Any]:
    """Normalises a triage report into the blocked-transfer detail body."""
    return {
        "message": "File transfer blocked by security triage.",
        "reason": report.get("reason")
        or report.get("ai_triage", {}).get("reason", "Flagged as unsafe."),
        "verdict": report.get("verdict", "UNKNOWN"),
        "stage": report.get("stage", "UNKNOWN"),
        "indicators": report.get("indicators", [])
    }


@app.post("/transfer")
async def transfer_file(file: UploadFile = File(...)):
    """
    Scans incoming payload. If SAFE, generates a 6-digit PIN and QR code for Phone B.
    If suspicious or malicious, rejects the transfer immediately.

    Use /transfer/stream instead for live per-tier progress updates.
    """
    cleanup_expired_vault_entries()

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    filename = file.filename or "unknown_file"
    report = analyzer.run_full_triage(contents, filename)

    if report["status"] != "APPROVED":
        raise HTTPException(status_code=403, detail=rejection_detail(report))

    return store_in_vault(contents, filename, report)


@app.post("/transfer/stream")
async def transfer_file_stream(file: UploadFile = File(...)):
    """
    Server-Sent Events variant of /transfer.

    Emits one `stage` event per pipeline transition, then a single `result`
    event carrying either the vault credential or the rejection detail.
    The response is always HTTP 200 so the browser can read the stream body
    for both outcomes.
    """
    cleanup_expired_vault_entries()

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    filename = file.filename or "unknown_file"

    def sse(event: str, payload: Dict[str, Any]) -> str:
        return f"event: {event}\ndata: {json.dumps(payload)}\n\n"

    async def event_stream():
        yield sse("stages", {"stages": analyzer.get_stage_catalog()})

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()

        done_marker = object()

        def emit(payload: Dict[str, Any]) -> None:
            # Runs on the worker thread, so hand the event to the event loop.
            loop.call_soon_threadsafe(queue.put_nowait, payload)

        def run_triage():
            # The worker owns the sentinel: every path must publish one so the
            # consumer never waits on an event that will not arrive.
            try:
                report = analyzer.run_full_triage(
                    contents, filename, progress=emit
                )
                emit({"event": "result", "report": report})
            except Exception as exc:
                emit({"event": "fatal", "message": str(exc)})
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, done_marker)

        task = loop.run_in_executor(None, run_triage)

        # Relay stage events until the worker signals completion. The sentinel
        # is queued behind every other event, so nothing is dropped even if the
        # worker finishes before the consumer asks for the next item.
        try:
            while True:
                update = await queue.get()

                if update is done_marker:
                    break

                event = update.pop("event", "stage")

                if event == "fatal":
                    yield sse("error", {
                        "message": update.get("message", "Triage failed.")
                    })
                    return

                if event == "result":
                    report = update.get("report", {})
                    if report.get("status") == "APPROVED":
                        yield sse("result", store_in_vault(contents, filename, report))
                    else:
                        yield sse("rejected", rejection_detail(report))
                    return

                yield sse("stage", update)
        finally:
            # Stop a still-running worker when the client disconnects early.
            if not task.done():
                task.cancel()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

@app.get("/transfer/status/{pin}")
async def transfer_status(pin: str):
    """
    Lightweight existence check for a transfer PIN.
    Used by the client to confirm a code before starting the download.
    Does not consume or modify the vault entry.
    """
    cleanup_expired_vault_entries()

    if pin not in VAULT:
        raise HTTPException(status_code=404, detail="Invalid or expired transfer PIN.")

    item = VAULT[pin]
    remaining = max(0, EXPIRATION_SECONDS - (time.time() - item["created_at"]))

    return {
        "valid": True,
        "pin": pin,
        "filename": item["filename"],
        "size_bytes": len(item["data"]),
        "content_type": item["content_type"],
        "expires_in_seconds": int(remaining),
        "verdict": item.get("triage_report", {}).get("verdict")
    }


# ============================================================================
# P2P Transfer Endpoints (WebTorrent)
# ============================================================================

@app.post("/transfer/p2p")
async def transfer_p2p(file: UploadFile = File(...)):
    """
    P2P file transfer: Scans file, creates WebTorrent magnet link, stores in vault.
    Returns PIN and magnet link for peer-to-peer distribution.
    """
    import hashlib
    import base64
    
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    # Run malware scan using existing analyzer
    report = analyzer.run_full_triage(contents, file.filename or "unknown")
    
    # Check if file was rejected
    if report.get("verdict") == "REJECTED":
        return {
            "status": "rejected",
            "reason": rejection_detail(report),
            "triage": report
        }
    
    # Generate info_hash for WebTorrent magnet link
    # Using SHA-1 hash of file content as BitTorrent info_hash
    info_hash = hashlib.sha1(contents).digest()
    info_hash_hex = info_hash.hex()
    
    # Create magnet link (WebTorrent compatible)
    # Format: magnet:?xt=urn:btih:<info_hash>&dn=<filename>&tr=<tracker_url>
    local_ip = cert_manager.get_local_ip()
    tracker_port = os.getenv("TRACKER_PORT", "8001")
    tracker_url = f"ws://{local_ip}:{tracker_port}"
    
    filename_encoded = file.filename.replace(" ", "%20") if file.filename else "file"
    magnet_link = f"magnet:?xt=urn:btih:{info_hash_hex}&dn={filename_encoded}&tr={tracker_url}"
    
    # Generate PIN and store in vault
    pin = f"{secrets.randbelow(900000) + 100000}"
    
    VAULT[pin] = {
        "filename": file.filename or "unknown",
        "content_type": report.get("file_info", {}).get("mime_type") or "application/octet-stream",
        "data": contents,
        "created_at": time.time(),
        "triage_report": report,
        "magnet_link": magnet_link,
        "info_hash": info_hash_hex,
        "size_bytes": len(contents)
    }
    
    receiver_url = f"https://{local_ip}:5000/static/p2p-receive.html?pin={pin}"
    
    return {
        "status": "approved",
        "pin": pin,
        "magnet_link": magnet_link,
        "receiver_url": receiver_url,
        "filename": file.filename,
        "size_bytes": len(contents),
        "expires_in_seconds": EXPIRATION_SECONDS,
        "triage": report
    }


@app.post("/transfer/email")
async def transfer_email(request: dict):
    """
    Send P2P transfer link via email.
    Request body: {"pin": "123456", "email": "recipient@example.com"}
    """
    import email_service
    
    pin = request.get("pin")
    recipient_email = request.get("email")
    
    if not pin or not recipient_email:
        raise HTTPException(status_code=400, detail="Missing pin or email in request.")
    
    cleanup_expired_vault_entries()
    
    if pin not in VAULT:
        raise HTTPException(status_code=404, detail="Invalid or expired transfer PIN.")
    
    item = VAULT[pin]
    magnet_link = item.get("magnet_link", "")
    filename = item.get("filename", "file")
    remaining = max(0, EXPIRATION_SECONDS - (time.time() - item["created_at"]))
    
    # Send email
    success = email_service.send_transfer_email(
        to_email=recipient_email,
        magnet_link=magnet_link,
        pin=pin,
        filename=filename,
        expires_in_seconds=int(remaining)
    )
    
    return {
        "sent": success,
        "pin": pin,
        "recipient": recipient_email
    }


@app.get("/transfer/p2p/{pin}")
async def transfer_p2p_status(pin: str):
    """
    Get P2P transfer metadata (magnet link, filename, etc.) for a given PIN.
    Used by receiver to initialize WebTorrent client.
    """
    cleanup_expired_vault_entries()
    
    if pin not in VAULT:
        raise HTTPException(status_code=404, detail="Invalid or expired transfer PIN.")
    
    item = VAULT[pin]
    remaining = max(0, EXPIRATION_SECONDS - (time.time() - item["created_at"]))
    
    return {
        "pin": pin,
        "magnet_link": item.get("magnet_link", ""),
        "filename": item.get("filename", "file"),
        "size_bytes": item.get("size_bytes", len(item["data"])),
        "content_type": item.get("content_type", "application/octet-stream"),
        "expires_in_seconds": int(remaining),
        "info_hash": item.get("info_hash", ""),
        "verdict": item.get("triage_report", {}).get("verdict")
    }


def safe_download_filename(filename: str) -> str:
    """
    Sanitises a user-supplied filename for use in a Content-Disposition header.
    Strips path separators and control characters, and falls back to a
    neutral name if nothing usable remains.
    """
    name = os.path.basename(str(filename or "")).strip()
    name = "".join(ch for ch in name if ch.isprintable())
    name = name.replace("\\", "").replace('"', "").replace("\r", "").replace("\n", "")
    return name or "download.bin"


@app.get("/download/{pin}")
async def download_file(pin: str, background_tasks: BackgroundTasks):
    """
    Allows Phone B to retrieve the file using the one-time PIN.
    Immediately deletes the file from memory upon serving.
    """
    cleanup_expired_vault_entries()

    if pin not in VAULT:
        raise HTTPException(status_code=404, detail="Invalid or expired transfer PIN.")

    item = VAULT[pin]
    filename = safe_download_filename(item["filename"])
    content_type = item["content_type"]
    file_bytes = item["data"]

    # Ephemeral auto-destruction: expunge from memory as soon as download begins
    del VAULT[pin]

    return Response(
        content=file_bytes,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
        }
    )