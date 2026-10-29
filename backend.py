import asyncio
import io
import json
import base64
import os
import time
import secrets
import hashlib
import subprocess
import re
from urllib.parse import urlparse
from typing import Dict, Any, Optional
from pydantic import BaseModel
import qrcode
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Request
from fastapi.responses import Response, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import analyzer
import cert_manager
import vault_manager
import email_service

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
P2P_EXPIRY_SECONDS = int(os.getenv("P2P_EXPIRY_SECONDS", "300"))
LOCAL_TRANSFER_EXPIRY_SECONDS = int(os.getenv("LOCAL_TRANSFER_EXPIRY_SECONDS", "60"))
EXPIRATION_SECONDS = P2P_EXPIRY_SECONDS  # Backwards-compatible alias for P2P callers.
MAX_P2P_FILE_BYTES = 2 * 1024 * 1024 * 1024
P2P_SEEDERS: Dict[str, Any] = {}

# Session OTP for domain access verification
def get_session_otp() -> str:
    return os.getenv("ETIPOS_ACCESS_OTP", "").strip()

ACTIVE_PORTAL_SESSIONS: set = set()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

def cleanup_expired_vault_entries():
    """Removes files that have exceeded the time-to-live."""
    now = time.time()
    expired_pins = [
        pin for pin, item in VAULT.items()
        if now - item["created_at"] > (
            LOCAL_TRANSFER_EXPIRY_SECONDS
            if item.get("transfer_type") == "local"
            else P2P_EXPIRY_SECONDS
        )
    ]
    for pin in expired_pins:
        item = VAULT.pop(pin)
        seeder = P2P_SEEDERS.pop(pin, None)
        if seeder:
            seeder.terminate()
            try:
                seeder.wait(timeout=2)
            except subprocess.TimeoutExpired:
                seeder.kill()
        seed_file = item.get("seed_file", {})
        seed_path = seed_file.get("path")
        if seed_path:
            try:
                os.unlink(seed_path)
            except OSError:
                pass
        seed_dir = seed_file.get("dir")
        if seed_dir:
            try:
                os.rmdir(seed_dir)
            except OSError:
                pass

def get_public_or_local_base_url() -> str:
    """Returns Cloudflare tunnel public domain if available, otherwise fallback to local IP."""
    tunnel_url = os.getenv("CLOUDFLARED_URL", "").strip().rstrip("/")
    if tunnel_url:
        return tunnel_url
    local_ip = cert_manager.get_local_ip()
    port = os.getenv("SERVER_PORT", "8000")
    scheme = "https" if os.getenv("TLS_CERT") else "http"
    return f"{scheme}://{local_ip}:{port}"


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

@app.get("/auth/status")
def auth_status(request: Request):
    """Checks whether access OTP is configured and whether client is authenticated."""
    otp = get_session_otp()
    if not otp:
        return {"required": False, "authenticated": True}
    
    session_token = request.cookies.get("etipos_session") or request.headers.get("X-Session-Token")
    authenticated = bool(session_token and session_token in ACTIVE_PORTAL_SESSIONS)
    return {"required": True, "authenticated": authenticated}

class VerifyOtpRequest(BaseModel):
    otp: str

@app.post("/auth/verify")
def verify_otp(body: VerifyOtpRequest, response: Response):
    """Verifies domain session OTP and sets session cookie."""
    otp = get_session_otp()
    if not otp:
        return {"status": "ok", "message": "No OTP protection configured."}
    
    entered_otp = body.otp.strip()
    if entered_otp != otp:
        raise HTTPException(status_code=401, detail="Invalid OTP code.")
    
    session_token = secrets.token_hex(24)
    ACTIVE_PORTAL_SESSIONS.add(session_token)
    response.set_cookie(
        key="etipos_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        max_age=86400
    )
    return {"status": "ok", "token": session_token}

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
    base_url = get_public_or_local_base_url()
    target_url = f"{base_url}/"
    png_bytes = generate_qr_bytes(target_url)
    return Response(content=png_bytes, media_type="image/png")

@app.get("/qr/{pin}")
def pin_qr(pin: str):
    """Generates a QR code image that directly opens the receiver tab on Phone B."""
    base_url = get_public_or_local_base_url()
    target_url = f"{base_url}/?pin={pin}"
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

def store_in_vault(
    contents: bytes, filename: str, report: Dict[str, Any], *, transfer_type: str = "local"
) -> Dict[str, Any]:
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
        "triage_report": report,
        "transfer_type": transfer_type,
    }

    base_url = get_public_or_local_base_url()

    return {
        "status": "APPROVED",
        "pin": pin,
        "qr_url": f"/qr/{pin}",
        "receiver_url": f"{base_url}/?pin={pin}",
        "expires_in_seconds": (
            LOCAL_TRANSFER_EXPIRY_SECONDS if transfer_type == "local" else P2P_EXPIRY_SECONDS
        ),
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
    ttl = LOCAL_TRANSFER_EXPIRY_SECONDS if item.get("transfer_type") == "local" else P2P_EXPIRY_SECONDS
    remaining = max(0, ttl - (time.time() - item["created_at"]))

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
async def transfer_p2p(request: Request, file: UploadFile = File(...)):
    """
    P2P file transfer: Scans file, creates WebTorrent magnet link, stores in vault.
    Returns PIN and magnet link for peer-to-peer distribution.
    """
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(contents) >= MAX_P2P_FILE_BYTES:
        raise HTTPException(status_code=413, detail="P2P files must be smaller than 2 GB.")
    
    # Run malware scan using existing analyzer
    report = analyzer.run_full_triage(contents, file.filename or "unknown")
    
    # Check if file was rejected
    if report.get("status") != "APPROVED":
        raise HTTPException(status_code=403, detail=rejection_detail(report))

    # Create actual BitTorrent metadata using the pinned create-torrent package.
    # File is scanned before being made available for seeding.
    import tempfile
    import json as json_module

    local_ip = cert_manager.get_local_ip()
    tracker_port = os.getenv("TRACKER_PORT", "8001")
    tracker_url = os.getenv("TRACKER_URL", f"ws://{local_ip}:{tracker_port}")
    is_https = bool(request and request.url.scheme == "https") or bool(os.getenv("TLS_CERT"))
    if tracker_url.startswith("ws://") and is_https:
        raise HTTPException(
            status_code=503,
            detail="Configure TRACKER_URL with a trusted wss:// endpoint for browser P2P from HTTPS.",
        )
    parsed_tracker = urlparse(tracker_url)
    if parsed_tracker.scheme not in {"ws", "wss"} or not parsed_tracker.netloc:
        raise HTTPException(status_code=503, detail="TRACKER_URL must be a valid ws:// or wss:// URL.")
    relay_dir = os.path.join(os.path.dirname(__file__), "p2p-relay")
    seed_name = f"{secrets.token_hex(16)}-{safe_download_filename(file.filename)}"
    seed_dir = os.path.join(tempfile.gettempdir(), "etipos-seed-vault")
    os.makedirs(seed_dir, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8", delete=False) as request_file:
        request_path = request_file.name
        json_module.dump({
            "filename": file.filename or "file",
            "announce": tracker_url,
            "seed_dir": seed_dir,
            "seed_name": seed_name,
        }, request_file)
    try:
        result = subprocess.run(
            ["node", os.path.join(relay_dir, "scripts", "create-torrent.cjs"), request_path],
            input=contents,
            capture_output=True,
            cwd=relay_dir,
            check=False,
        )
        if result.returncode != 0:
            raise HTTPException(status_code=503, detail="Torrent metadata generator unavailable.")
        torrent_metadata = json_module.loads(result.stdout)
    finally:
        try:
            os.unlink(request_path)
        except OSError:
            pass

    magnet_link = torrent_metadata["magnetURI"]
    info_hash_hex = torrent_metadata["infoHash"]
    if not re.fullmatch(r"[0-9a-fA-F]{40}", info_hash_hex):
        raise HTTPException(status_code=503, detail="Torrent metadata contains an invalid info hash.")
    if not str(magnet_link).startswith(f"magnet:?xt=urn:btih:{info_hash_hex}"):
        raise HTTPException(status_code=503, detail="Torrent magnet info hash does not match generated metadata.")
    if tracker_url not in str(magnet_link):
        raise HTTPException(status_code=503, detail="Torrent magnet is missing the configured tracker.")

    seed_path = torrent_metadata["tempPath"]
    seed_file = {
        "path": seed_path,
        "dir": torrent_metadata["tempDir"],
    }
    try:
        torrent_bytes = bytes(torrent_metadata["torrent"])
        if not torrent_bytes:
            raise ValueError("empty torrent metadata")
        torrent_metadata["torrent"] = base64.b64encode(torrent_bytes).decode("ascii")
    except (TypeError, ValueError):
        raise HTTPException(status_code=503, detail="Torrent metadata encoding failed.")
    
    # Generate PIN and store in vault
    pin = f"{secrets.randbelow(900000) + 100000}"
    
    VAULT[pin] = {
        "filename": file.filename or "unknown",
        "content_type": report.get("file_info", {}).get("mime_type") or "application/octet-stream",
        "data": contents,
        "created_at": time.time(),
        "triage_report": report,
        "transfer_type": "p2p",
        "magnet_link": magnet_link,
        "info_hash": info_hash_hex,
        "sha256": torrent_metadata["sha256"],
        "size_bytes": len(contents),
        "torrent": torrent_metadata["torrent"],
        "seed_file": seed_file,
    }

    # Start a real WebTorrent seeder over the exact approved payload and
    # metadata created above. The helper stays alive until transfer expiry.
    seeder = subprocess.Popen(
        ["node", os.path.join(relay_dir, "scripts", "seed-torrent.cjs"), seed_path, torrent_metadata["torrent"]],
        cwd=relay_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "TRACKER_URL": tracker_url},
    )
    P2P_SEEDERS[pin] = seeder

    server_port = os.getenv("SERVER_PORT", "8000")
    web_scheme = "https" if os.getenv("TLS_CERT") else "http"
    receiver_url = f"{web_scheme}://{local_ip}:{server_port}/static/p2p-receive.html?pin={pin}"
    
    return {
        "status": "approved",
        "pin": pin,
        "magnet_link": magnet_link,
        "info_hash": info_hash_hex,
        "sha256": torrent_metadata["sha256"],
        "receiver_url": receiver_url,
        "filename": file.filename,
        "size_bytes": len(contents),
        "expires_in_seconds": P2P_EXPIRY_SECONDS,
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
    ttl = LOCAL_TRANSFER_EXPIRY_SECONDS if item.get("transfer_type") == "local" else P2P_EXPIRY_SECONDS
    remaining = max(0, ttl - (time.time() - item["created_at"]))
    
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
    if item.get("transfer_type") != "p2p":
        raise HTTPException(status_code=404, detail="Invalid or expired P2P transfer PIN.")
    remaining = max(0, P2P_EXPIRY_SECONDS - (time.time() - item["created_at"]))
    
    return {
        "pin": pin,
        "magnet_link": item.get("magnet_link", ""),
        "filename": item.get("filename", "file"),
        "size_bytes": item.get("size_bytes", len(item["data"])),
        "content_type": item.get("content_type", "application/octet-stream"),
        "expires_in_seconds": int(remaining),
        "info_hash": item.get("info_hash", ""),
        "torrent": item.get("torrent"),
        "sha256": item.get("sha256") or hashlib.sha256(item["data"]).hexdigest(),
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
    if item.get("transfer_type") == "p2p":
        raise HTTPException(status_code=400, detail="P2P transfers must be downloaded with WebTorrent.")
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


# =============================================================================
# Phase 2: Internet Distance Transfer & Email Notification Endpoints
# =============================================================================

class NotifyEmailRequest(BaseModel):
    token: str
    recipient_email: str
    sender_name: Optional[str] = "Someone"
    public_url: Optional[str] = None


@app.post("/transfer/internet")
async def transfer_file_internet(file: UploadFile = File(...), request: Request = None):
    """
    Scans incoming payload via 3-tier security pipeline.
    If APPROVED, stores it in the persistent disk-backed vault with a 24-hour TTL
    and returns a secret token and global download URL.
    """
    vault_manager.cleanup_expired_vault()

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    filename = file.filename or "unknown_file"
    report = analyzer.run_full_triage(contents, filename)

    if report.get("status") != "APPROVED":
        raise HTTPException(status_code=403, detail=rejection_detail(report))

    ttl_hours = int(os.environ.get("VAULT_TTL_HOURS", "24"))
    metadata = vault_manager.store_file(contents, filename, report, ttl_seconds=ttl_hours * 3600)

    # Determine base public URL
    configured_public_url = os.environ.get("PUBLIC_TUNNEL_URL", "").rstrip("/")
    if not configured_public_url:
        local_ip = cert_manager.get_local_ip()
        base_url = f"https://{local_ip}:8000"
    else:
        base_url = configured_public_url

    download_url = f"{base_url}/download/token/{metadata['token']}"
    portal_download_url = f"{base_url}/?token={metadata['token']}"

    return {
        "status": "APPROVED",
        "token": metadata["token"],
        "filename": filename,
        "size_bytes": metadata["size_bytes"],
        "expires_in_hours": ttl_hours,
        "download_url": download_url,
        "portal_url": portal_download_url,
        "triage": report
    }


@app.post("/transfer/notify")
async def notify_recipient_email(req: NotifyEmailRequest):
    """
    Sends the secure file download link to the recipient's email via Gmail SMTP.
    """
    metadata = vault_manager.get_file_metadata(req.token)
    if not metadata:
        raise HTTPException(status_code=404, detail="File token not found or expired.")

    # Determine public URL
    configured_url = req.public_url or os.environ.get("PUBLIC_TUNNEL_URL", "")
    configured_url = configured_url.rstrip("/")
    if not configured_url:
        local_ip = cert_manager.get_local_ip()
        base_url = f"https://{local_ip}:8000"
    else:
        base_url = configured_url

    download_url = f"{base_url}/download/token/{req.token}"
    hours_left = max(1, int((metadata.get("expires_at", 0) - time.time()) // 3600))

    result = email_service.send_transfer_email(
        to_email=req.recipient_email,
        download_url=download_url,
        filename=metadata.get("filename", "file"),
        size_bytes=metadata.get("size_bytes", 0),
        expires_in_hours=hours_left,
        sender_name=req.sender_name
    )

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to send email."))

    return {"status": "SENT", "recipient": req.recipient_email}


@app.get("/transfer/token/status/{token}")
async def token_transfer_status(token: str):
    """
    Status check for token-based internet transfers.
    """
    vault_manager.cleanup_expired_vault()
    metadata = vault_manager.get_file_metadata(token)
    if not metadata:
        raise HTTPException(status_code=404, detail="Invalid or expired download link.")

    remaining_sec = max(0, int(metadata.get("expires_at", 0) - time.time()))

    return {
        "valid": True,
        "token": token,
        "filename": metadata.get("filename"),
        "size_bytes": metadata.get("size_bytes"),
        "content_type": metadata.get("content_type"),
        "expires_in_seconds": remaining_sec,
        "verdict": metadata.get("triage_report", {}).get("verdict")
    }


@app.get("/download/token/{token}")
async def download_token_file(token: str, background_tasks: BackgroundTasks, request: Request):
    """
    Allows recipient anywhere on the internet to retrieve the file via token.
    Ignores bot previews/HEAD requests, supports byte ranges, and cleans up cleanly.
    """
    # Reject or return empty for HEAD/preview crawlers without deleting
    user_agent = request.headers.get("user-agent", "").lower()
    is_crawler = any(bot in user_agent for bot in [
        "whatsapp", "telegram", "facebookexternalhit", "twitterbot", "slackbot", "discordbot", "curl", "preview"
    ])

    vault_manager.cleanup_expired_vault()

    result = vault_manager.get_file_payload(token)
    if not result:
        raise HTTPException(status_code=404, detail="Invalid, expired, or already-downloaded file.")

    contents, metadata = result
    filename = safe_download_filename(metadata.get("filename", "file"))
    content_type = metadata.get("content_type", "application/octet-stream")

    # If it's a social media / chat preview crawler, don't trigger download consumption
    if is_crawler:
        return Response(
            content=b"",
            media_type=content_type,
            headers={
                "Content-Disposition": f'inline; filename="{filename}"',
                "Content-Length": "0"
            }
        )

    # Clean up after the file has been successfully streamed to the client
    # Schedule deletion after a grace window (e.g., 60 seconds) so chunked/range or resume requests don't instantly break
    background_tasks.add_task(schedule_token_deletion, token, delay_seconds=60)

    return Response(
        content=contents,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(contents)),
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
        }
    )


async def schedule_token_deletion(token: str, delay_seconds: int = 60):
    """Waits for the download transfer to complete before removing from disk."""
    try:
        await asyncio.sleep(delay_seconds)
        vault_manager.delete_file(token)
    except Exception:
        pass


@app.get("/tunnel-url")
async def get_tunnel_url():
    """
    Returns the auto-launched cloudflared public tunnel URL if active.
    Used by frontend to populate long distance sharing links.
    """
    url = os.getenv("CLOUDFLARED_URL", "").strip()
    return {"url": url if url else None}


@app.post("/share-target")
async def share_target_upload(file: UploadFile = File(...)):
    """
    PWA Web Share Target handler. Android shares files straight here.
    """
    return await transfer_file_internet(file)

