import os
import sys
import io
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from gateway_server.server import app
from protocols.crypto_engine import CryptoEngine, PayloadChunker
from tests.test_static_analyzer import create_synthetic_malicious_apk, create_synthetic_benign_apk

client = TestClient(app)


def test_handshake_and_chunked_upload_flow():
    # 1. Client generates X25519 keypair
    client_priv, client_pub = CryptoEngine.generate_x25519_keypair()
    client_pub_b64 = CryptoEngine.public_key_to_b64(client_pub)

    # 2. Call Handshake
    res = client.post("/api/handshake", json={
        "sender_id": "phone-a-android",
        "client_ephemeral_public_key": client_pub_b64
    })
    assert res.status_code == 200
    data = res.json()
    session_id = data["session_id"]
    gw_pub_b64 = data["gateway_ephemeral_public_key"]

    # 3. Derive keys on client side
    gw_pub = CryptoEngine.b64_to_public_key(gw_pub_b64)
    derived = CryptoEngine.derive_session_keys(client_priv, gw_pub)

    # 4. Chunk benign APK and upload
    apk_bytes = create_synthetic_benign_apk()
    payload_id = "test-payload-123"
    chunks = PayloadChunker.chunk_payload(
        apk_bytes,
        session_id=session_id,
        payload_id=payload_id,
        aes_key=derived["aes_key"],
        hmac_key=derived["hmac_key"],
        chunk_size=512
    )

    for chunk in chunks:
        c_res = client.post("/api/payload/chunk", json=chunk)
        assert c_res.status_code == 200

    # 5. Trigger assemble and inspect
    insp_res = client.post(f"/api/payload/{payload_id}/assemble-and-inspect?session_id={session_id}&filename=calc.apk")
    assert insp_res.status_code == 200
    report = insp_res.json()

    assert report["verdict"] == "PASS"
    assert report["composite_risk_score"] < 3.5
    assert "gateway_signature" in report


def test_direct_inspect_blocked_malware():
    mal_apk = create_synthetic_malicious_apk()
    files = {"file": ("trojan.apk", mal_apk, "application/vnd.android.package-archive")}

    res = client.post("/api/payload/inspect-direct", files=files)
    assert res.status_code == 200
    report = res.json()

    assert report["verdict"] in ["QUARANTINE", "BLOCK"]
    assert report["composite_risk_score"] >= 3.5
    assert len(report["static_analysis"]["dangerous_permissions"]) >= 3


def test_stats_endpoint():
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_inspected" in stats
    assert "passed" in stats


if __name__ == "__main__":
    pytest.main(["-v", __file__])

