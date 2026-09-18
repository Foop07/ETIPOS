import base64
from fastapi.testclient import TestClient
from backend import app

client = TestClient(app)

def test_health():
    print("\n[+] Testing /health endpoint...")
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    print("Health Status:", data)
    assert data["status"] == "HEALTHY"
    assert data["components"]["tier1_magika"] == "ONLINE"
    assert data["components"]["tier2_clamav"] == "ONLINE"
    assert data["components"]["tier3_ollama_qwen"] == "ONLINE"

def test_clean_file_transfer_and_ephemeral_download():
    print("\n[+] Testing clean file transfer...")
    test_content = b"Confidential document content for secure peer-to-peer relay."
    response = client.post(
        "/transfer",
        files={"file": ("secret.txt", test_content, "text/plain")}
    )
    assert response.status_code == 200
    result = response.json()
    pin = result["pin"]
    print(f"Transfer Approved! Generated 6-digit PIN: {pin}")
    assert len(pin) == 6
    assert result["status"] == "APPROVED"

    # Step 2: Download file using PIN
    print(f"[+] Downloading file using PIN: {pin}...")
    dl_response = client.get(f"/download/{pin}")
    assert dl_response.status_code == 200
    assert dl_response.content == test_content
    print("File downloaded successfully and verified matching byte-for-byte!")

    # Step 3: Attempt second download (should fail because file was expunged)
    print("[+] Verifying ephemeral auto-destruction (second download should 404)...")
    second_dl = client.get(f"/download/{pin}")
    assert second_dl.status_code == 404
    print("Vault correctly expunged file immediately after single download!")

def test_block_double_extension_attack():
    print("\n[+] Testing malicious double-extension trap...")
    response = client.post(
        "/transfer",
        files={"file": ("photo.jpg.exe", b"MZ_binary_executable_data", "application/octet-stream")}
    )
    print("Response Status:", response.status_code)
    assert response.status_code == 403
    print("Attack successfully blocked:", response.json())

def test_block_clamav_eicar_signature():
    print("\n[+] Testing ClamAV known-signature block (EICAR)...")
    eicar = base64.b64decode('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
    response = client.post(
        "/transfer",
        files={"file": ("eicar_test.com", eicar, "application/octet-stream")}
    )
    print("Response Status:", response.status_code)
    assert response.status_code == 403
    print("Known virus successfully intercepted by ClamAV:", response.json())

def test_portal_and_network_info():
    print("\n[+] Testing /network-info and Web Portal...")
    res = client.get("/network-info")
    assert res.status_code == 200
    net_data = res.json()
    print("Network Info:", net_data)
    assert "local_ip" in net_data
    assert "https_url" in net_data

    # Test portal serving
    portal_res = client.get("/")
    assert portal_res.status_code == 200
    assert "ETIPOS Fortress Relay" in portal_res.text
    print("Web Portal served successfully with mobile UI!")

def test_qr_generation():
    print("\n[+] Testing QR Code endpoints...")
    # Portal QR
    qr_res = client.get("/qr-portal")
    assert qr_res.status_code == 200
    assert qr_res.headers["content-type"] == "image/png"
    assert len(qr_res.content) > 100

    # Transfer PIN QR
    pin_qr_res = client.get("/qr/999888")
    assert pin_qr_res.status_code == 200
    assert pin_qr_res.headers["content-type"] == "image/png"
    assert len(pin_qr_res.content) > 100
    print("QR Code generation validated for both portal and transfer PINs!")

if __name__ == "__main__":
    test_health()
    test_portal_and_network_info()
    test_qr_generation()
    test_clean_file_transfer_and_ephemeral_download()
    test_block_double_extension_attack()
    test_block_clamav_eicar_signature()
    print("\n[SUCCESS] ALL PHASE 2, 3 & 4 TESTS PASSED PERFECTLY!")
