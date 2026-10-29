import hashlib
import io
import json
import subprocess
import time

from fastapi.testclient import TestClient

import backend
from backend import app, VAULT

client = TestClient(app)


def approved_report():
    return {
        "status": "APPROVED",
        "verdict": "APPROVED",
        "tier1_magic": {"mime_type": "application/pdf"},
        "tier2_clamav": {"status": "CLEAN"},
        "tier3_llm": {"verdict": "APPROVED"},
    }


def test_local_transfer_scans_and_rejects_before_storing(monkeypatch):
    monkeypatch.setattr("analyzer.run_full_triage", lambda *_: {
        "status": "BLOCKED", "verdict": "MALICIOUS", "reason": "test malware"
    })
    VAULT.clear()

    response = client.post("/transfer", files={"file": ("bad.bin", b"bad", "application/octet-stream")})

    assert response.status_code == 403
    assert response.json()["detail"]["verdict"] == "MALICIOUS"
    assert VAULT == {}


def test_local_transfer_pin_status_download_and_checksum(monkeypatch):
    monkeypatch.setattr("analyzer.run_full_triage", lambda *_: approved_report())
    monkeypatch.setattr(backend, "LOCAL_TRANSFER_EXPIRY_SECONDS", 120)
    monkeypatch.setattr("cert_manager.get_local_ip", lambda: "127.0.0.1")
    VAULT.clear()
    payload = b"local transfer checksum test"

    response = client.post("/transfer", files={"file": ("sample.pdf", payload, "application/pdf")})

    assert response.status_code == 200
    pin = response.json()["pin"]
    assert response.json()["expires_in_seconds"] == 120
    status = client.get(f"/transfer/status/{pin}")
    assert status.status_code == 200
    assert status.json()["filename"] == "sample.pdf"
    download = client.get(f"/download/{pin}")
    assert download.status_code == 200
    assert hashlib.sha256(download.content).digest() == hashlib.sha256(payload).digest()
    VAULT.clear()


def test_local_transfer_expiry_is_independent_of_p2p_setting(monkeypatch):
    monkeypatch.setattr(backend, "P2P_EXPIRY_SECONDS", 1)
    monkeypatch.setattr(backend, "LOCAL_TRANSFER_EXPIRY_SECONDS", 90)
    VAULT.clear()
    VAULT["111111"] = {
        "filename": "local.txt", "content_type": "text/plain", "data": b"x",
        "created_at": time.time() - 2, "triage_report": approved_report(), "transfer_type": "local",
    }
    VAULT["222222"] = {
        "filename": "p2p.txt", "content_type": "text/plain", "data": b"x",
        "created_at": time.time() - 2, "triage_report": approved_report(), "transfer_type": "p2p",
    }

    backend.cleanup_expired_vault_entries()

    assert "111111" in VAULT
    assert "222222" not in VAULT
    VAULT.clear()


def test_local_transfer_status_uses_local_ttl(monkeypatch):
    monkeypatch.setattr(backend, "P2P_EXPIRY_SECONDS", 2)
    monkeypatch.setattr(backend, "LOCAL_TRANSFER_EXPIRY_SECONDS", 90)
    VAULT.clear()
    VAULT["333333"] = {
        "filename": "local.txt", "content_type": "text/plain", "data": b"x",
        "created_at": time.time() - 1, "triage_report": approved_report(), "transfer_type": "local",
    }

    response = client.get("/transfer/status/333333")

    assert response.status_code == 200
    assert response.json()["expires_in_seconds"] > 0
    VAULT.clear()


def test_p2p_upload_rejects_malware_without_creating_torrent(monkeypatch):
    monkeypatch.setattr("analyzer.run_full_triage", lambda *_: {
        "status": "BLOCKED", "verdict": "MALICIOUS", "reason": "unsafe"
    })
    VAULT.clear()

    response = client.post("/transfer/p2p", files={"file": ("bad.bin", b"bad", "application/octet-stream")})

    assert response.status_code == 403
    assert VAULT == {}


def test_https_p2p_requires_wss_tracker_before_scanning(monkeypatch):
    monkeypatch.setattr(backend, "TLS_CERT", "", raising=False)
    monkeypatch.setattr("analyzer.run_full_triage", lambda *_: approved_report())
    monkeypatch.setenv("TLS_CERT", "local-cert.pem")
    VAULT.clear()

    response = client.post("/transfer/p2p", files={"file": ("test.txt", b"payload", "text/plain")})

    assert response.status_code == 503
    assert "wss://" in response.json()["detail"]
    assert VAULT == {}


def test_p2p_accepts_configured_wss_tracker_url(monkeypatch):
    monkeypatch.setattr(backend, "TLS_CERT", "", raising=False)
    monkeypatch.setattr("analyzer.run_full_triage", lambda *_: approved_report())
    monkeypatch.setenv("TLS_CERT", "local-cert.pem")
    monkeypatch.setenv("TRACKER_URL", "wss://trusted.local/tracker")
    monkeypatch.setattr("cert_manager.get_local_ip", lambda: "127.0.0.1")

    class DummySeeder:
        def terminate(self): pass
        def wait(self, timeout=None): pass
    monkeypatch.setattr(backend.subprocess, "Popen", lambda *_args, **_kwargs: DummySeeder())
    payload = b"wss configured payload"
    generated = {
        "infoHash": "c" * 40,
        "magnetURI": "magnet:?xt=urn:btih:" + "c" * 40 + "&tr=wss://trusted.local/tracker",
        "torrent": [100, 56, 58, 97],
        "tempPath": "seed/wss.txt",
        "tempDir": "seed",
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    monkeypatch.setattr(backend.subprocess, "run", lambda *args, **_kwargs: subprocess.CompletedProcess(
        args[0], 0, json.dumps(generated).encode(), b""
    ))

    response = client.post("/transfer/p2p", files={"file": ("wss.txt", payload, "text/plain")})

    assert response.status_code == 200
    assert "wss://trusted.local/tracker" in response.json()["magnet_link"]
    VAULT.clear()


def test_p2p_uses_real_torrent_metadata_and_reports_checksum(monkeypatch):
    monkeypatch.setattr(backend, "TLS_CERT", "", raising=False)
    monkeypatch.setattr("analyzer.run_full_triage", lambda *_: approved_report())
    monkeypatch.setattr("cert_manager.get_local_ip", lambda: "127.0.0.1")

    class DummySeeder:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

    monkeypatch.setattr(backend.subprocess, "Popen", lambda *_args, **_kwargs: DummySeeder())
    payload = b"valid torrent data"
    torrent_data = {
        "infoHash": "a" * 40,
        "magnetURI": "magnet:?xt=urn:btih:" + "a" * 40 + "&tr=ws://127.0.0.1:8001",
        "torrent": [100, 56, 58, 97],
        "tempPath": "seed/sample.txt",
        "tempDir": "seed",
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    monkeypatch.setattr(backend.subprocess, "run", lambda *args, **_kwargs: subprocess.CompletedProcess(
        args[0], 0, json.dumps(torrent_data).encode(), b""
    ))
    VAULT.clear()

    response = client.post("/transfer/p2p", files={"file": ("sample.txt", payload, "text/plain")})

    assert response.status_code == 200
    data = response.json()
    assert data["info_hash"] == "a" * 40
    assert data["magnet_link"].startswith("magnet:?xt=urn:btih:" + "a" * 40)
    assert data["sha256"] == hashlib.sha256(payload).hexdigest()
    assert data["receiver_url"].endswith(f"/static/p2p-receive.html?pin={data['pin']}")
    VAULT.clear()


def test_p2p_transfer_creates_torrent_and_returns_magnet(monkeypatch):
    monkeypatch.setattr("analyzer.run_full_triage", lambda *_: approved_report())
    monkeypatch.setattr("cert_manager.get_local_ip", lambda: "127.0.0.1")

    class DummySeeder:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

    monkeypatch.setattr(backend.subprocess, "Popen", lambda *_args, **_kwargs: DummySeeder())
    payload = b"Test PDF content"
    torrent_data = {
        "infoHash": "b" * 40,
        "magnetURI": "magnet:?xt=urn:btih:" + "b" * 40 + "&tr=ws://127.0.0.1:8001",
        "torrent": [100, 56, 58, 97],
        "tempPath": "seed/test.pdf",
        "tempDir": "seed",
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    monkeypatch.setattr(backend.subprocess, "run", lambda *args, **_kwargs: subprocess.CompletedProcess(
        args[0], 0, json.dumps(torrent_data).encode(), b""
    ))

    response = client.post("/transfer/p2p", files={"file": ("test.pdf", payload, "application/pdf")})

    assert response.status_code == 200
    data = response.json()
    assert data["pin"].isdigit() and len(data["pin"]) == 6
    assert data["magnet_link"].startswith("magnet:?xt=urn:btih:")
    assert data["filename"] == "test.pdf"
    VAULT.clear()


def test_p2p_email_sends_link(monkeypatch):
    VAULT["123456"] = {
        "filename": "test.pdf", "content_type": "application/pdf", "data": b"test content",
        "created_at": time.time(), "triage_report": approved_report(), "transfer_type": "p2p",
        "magnet_link": "magnet:?xt=urn:btih:abc123",
    }
    sent = {}

    def mock_send_email(to_email, magnet_link, pin, filename, expires_in_seconds):
        sent.update(to=to_email, pin=pin, magnet=magnet_link)
        return True

    monkeypatch.setattr("email_service.send_transfer_email", mock_send_email)
    response = client.post("/transfer/email", json={"pin": "123456", "email": "recipient@example.com"})
    assert response.status_code == 200
    assert response.json()["sent"] is True
    assert sent["to"] == "recipient@example.com"
    VAULT.clear()


def test_p2p_status_returns_magnet():
    VAULT["654321"] = {
        "filename": "document.pdf", "content_type": "application/pdf", "data": b"test content",
        "created_at": time.time(), "triage_report": {"verdict": "APPROVED"},
        "transfer_type": "p2p", "magnet_link": "magnet:?xt=urn:btih:xyz789", "size_bytes": 12,
    }
    response = client.get("/transfer/p2p/654321")
    assert response.status_code == 200
    assert response.json()["magnet_link"] == "magnet:?xt=urn:btih:xyz789"
    assert response.json()["filename"] == "document.pdf"
    VAULT.clear()


def test_p2p_status_returns_404_for_invalid_pin():
    assert client.get("/transfer/p2p/999999").status_code == 404


def test_p2p_transfer_rejects_file_at_2gb_limit(monkeypatch):
    monkeypatch.setattr(backend, "MAX_P2P_FILE_BYTES", 2)
    response = client.post("/transfer/p2p", files={"file": ("large.bin", b"123", "application/octet-stream")})
    assert response.status_code == 413


def test_p2p_transfer_rejects_non_approved_scan(monkeypatch):
    monkeypatch.setattr("analyzer.run_full_triage", lambda *_: {"status": "REJECTED", "verdict": "MALICIOUS"})
    response = client.post("/transfer/p2p", files={"file": ("bad.bin", b"content", "application/octet-stream")})
    assert response.status_code == 403
    assert response.json()["detail"]["verdict"] == "MALICIOUS"
