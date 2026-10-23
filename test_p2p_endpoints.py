import pytest
from fastapi.testclient import TestClient
from backend import app, VAULT
import io

client = TestClient(app)


def test_p2p_transfer_creates_torrent_and_returns_magnet(monkeypatch):
    """Test that POST /transfer/p2p scans file and returns magnet link + PIN"""
    # Mock analyzer to return APPROVED status
    def mock_triage(contents, filename):
        return {
            "verdict": "APPROVED",
            "tier1_magic": {"mime_type": "application/pdf"},
            "tier2_clamav": {"status": "CLEAN"},
            "tier3_llm": {"verdict": "APPROVED"}
        }
    
    monkeypatch.setattr("analyzer.run_full_triage", mock_triage)
    
    # Create a test file
    test_file_content = b"Test PDF content"
    files = {"file": ("test.pdf", io.BytesIO(test_file_content), "application/pdf")}
    
    response = client.post("/transfer/p2p", files=files)
    
    assert response.status_code == 200
    data = response.json()
    
    # Check response structure
    assert "pin" in data
    assert "magnet_link" in data
    assert "filename" in data
    assert "expires_in_seconds" in data
    
    # Verify PIN format (6 digits)
    assert len(data["pin"]) == 6
    assert data["pin"].isdigit()
    
    # Verify magnet link format
    assert data["magnet_link"].startswith("magnet:?")
    
    # Verify filename
    assert data["filename"] == "test.pdf"


def test_p2p_email_sends_link(monkeypatch):
    """Test that POST /transfer/email sends email with PIN"""
    import time
    
    # Pre-populate VAULT with test data
    test_pin = "123456"
    VAULT[test_pin] = {
        "filename": "test.pdf",
        "content_type": "application/pdf",
        "data": b"test content",
        "created_at": time.time(),
        "triage_report": {"verdict": "APPROVED"},
        "magnet_link": "magnet:?xt=urn:btih:abc123"
    }
    
    # Mock email service
    email_sent = {"called": False}
    
    def mock_send_email(to_email, magnet_link, pin, filename, expires_in_seconds):
        email_sent["called"] = True
        email_sent["to"] = to_email
        email_sent["pin"] = pin
        return True
    
    monkeypatch.setattr("email_service.send_transfer_email", mock_send_email)
    
    response = client.post("/transfer/email", json={
        "pin": test_pin,
        "email": "recipient@example.com"
    })
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["sent"] is True
    assert email_sent["called"] is True
    assert email_sent["to"] == "recipient@example.com"
    assert email_sent["pin"] == test_pin
    
    # Cleanup
    del VAULT[test_pin]


def test_p2p_status_returns_magnet(monkeypatch):
    """Test that GET /transfer/p2p/{pin} returns torrent metadata"""
    import time
    
    # Pre-populate VAULT with test data
    test_pin = "654321"
    VAULT[test_pin] = {
        "filename": "document.pdf",
        "content_type": "application/pdf",
        "data": b"test content",
        "created_at": time.time(),
        "triage_report": {"verdict": "APPROVED"},
        "magnet_link": "magnet:?xt=urn:btih:xyz789",
        "size_bytes": 12
    }
    
    response = client.get(f"/transfer/p2p/{test_pin}")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["magnet_link"] == "magnet:?xt=urn:btih:xyz789"
    assert data["filename"] == "document.pdf"
    assert data["content_type"] == "application/pdf"
    assert "size_bytes" in data
    
    # Cleanup
    del VAULT[test_pin]


def test_p2p_status_returns_404_for_invalid_pin():
    """Test that GET /transfer/p2p/{pin} returns 404 for non-existent PIN"""
    response = client.get("/transfer/p2p/999999")
    
    assert response.status_code == 404
