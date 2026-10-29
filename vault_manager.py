import os
import time
import json
import secrets
import shutil
from typing import Dict, Any, Optional, Tuple

VAULT_DIR = os.environ.get("ETIPOS_VAULT_DIR", os.path.join(os.path.dirname(__file__), "vault"))
os.makedirs(VAULT_DIR, exist_ok=True)

DEFAULT_TTL_HOURS = int(os.environ.get("VAULT_TTL_HOURS", "24"))
DEFAULT_TTL_SECONDS = DEFAULT_TTL_HOURS * 3600

def generate_token() -> str:
    """Generate a high-entropy URL-safe token (32 chars) for distance transfers."""
    return secrets.token_urlsafe(24)

def store_file(contents: bytes, filename: str, report: Dict[str, Any], ttl_seconds: int = DEFAULT_TTL_SECONDS) -> Dict[str, Any]:
    """
    Saves an approved payload to a persistent disk folder under `vault/{token}/`.
    Includes metadata and security report.
    """
    token = generate_token()
    folder_path = os.path.join(VAULT_DIR, token)
    os.makedirs(folder_path, exist_ok=True)

    file_path = os.path.join(folder_path, "payload.bin")
    with open(file_path, "wb") as f:
        f.write(contents)

    content_type = report.get("file_info", {}).get("mime_type") or "application/octet-stream"
    created_at = time.time()
    expires_at = created_at + ttl_seconds

    metadata = {
        "token": token,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": len(contents),
        "created_at": created_at,
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
        "triage_report": report
    }

    meta_path = os.path.join(folder_path, "meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata

def get_file_metadata(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves metadata without reading the whole payload if present and not expired."""
    folder_path = os.path.join(VAULT_DIR, token)
    meta_path = os.path.join(folder_path, "meta.json")
    if not os.path.exists(meta_path):
        return None

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except Exception:
        return None

    if time.time() > metadata.get("expires_at", 0):
        delete_file(token)
        return None

    return metadata

def get_file_payload(token: str) -> Optional[Tuple[bytes, Dict[str, Any]]]:
    """Returns (bytes, metadata) if present and not expired."""
    metadata = get_file_metadata(token)
    if not metadata:
        return None

    folder_path = os.path.join(VAULT_DIR, token)
    file_path = os.path.join(folder_path, "payload.bin")
    if not os.path.exists(file_path):
        delete_file(token)
        return None

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        return data, metadata
    except Exception:
        return None

def delete_file(token: str) -> bool:
    """Removes a vault folder completely."""
    folder_path = os.path.join(VAULT_DIR, token)
    if os.path.exists(folder_path):
        try:
            shutil.rmtree(folder_path, ignore_errors=True)
            return True
        except Exception:
            return False
    return False

def cleanup_expired_vault() -> int:
    """Scans vault directory and removes any expired tokens."""
    if not os.path.exists(VAULT_DIR):
        return 0

    deleted_count = 0
    now = time.time()
    try:
        for entry in os.listdir(VAULT_DIR):
            entry_path = os.path.join(VAULT_DIR, entry)
            if not os.path.isdir(entry_path):
                continue
            meta_path = os.path.join(entry_path, "meta.json")
            if not os.path.exists(meta_path):
                # Orphaned or corrupted folder
                shutil.rmtree(entry_path, ignore_errors=True)
                deleted_count += 1
                continue
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                if now > meta.get("expires_at", 0):
                    shutil.rmtree(entry_path, ignore_errors=True)
                    deleted_count += 1
            except Exception:
                shutil.rmtree(entry_path, ignore_errors=True)
                deleted_count += 1
    except Exception:
        pass

    return deleted_count

