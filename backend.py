import io
import os
import time
import secrets
from typing import Dict, Any
import qrcode
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import Response, FileResponse
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

@app.post("/transfer")
async def transfer_file(file: UploadFile = File(...)):
    """
    Scans incoming payload. If SAFE, generates a 6-digit PIN and QR code for Phone B.
    If suspicious or malicious, rejects the transfer immediately.
    """
    cleanup_expired_vault_entries()

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    filename = file.filename or "unknown_file"
    report = analyzer.run_full_triage(contents, filename)

    if report["status"] != "APPROVED":
        raise HTTPException(
            status_code=403,
            detail={
                "message": "File transfer blocked by security triage.",
                "reason": report.get("reason") or report.get("ai_triage", {}).get("reason", "Flagged as unsafe."),
                "verdict": report["verdict"],
                "stage": report["stage"]
            }
        )

    # Cryptographically random 6-digit PIN
    pin = f"{secrets.randbelow(900000) + 100000}"
    
    # Store in ephemeral vault
    VAULT[pin] = {
        "filename": filename,
        "content_type": report["file_info"]["mime_type"] or "application/octet-stream",
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
    filename = item["filename"]
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