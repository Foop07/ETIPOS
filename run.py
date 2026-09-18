import os
import sys
import uvicorn
import qrcode
import cert_manager
import analyzer

# Ensure terminal can print UTF-8 characters and QR blocks on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    print("=" * 60)
    print("  ETIPOS SECURE LOCAL WIRELESS RELAY - FORTRESS GATEWAY")
    print("=" * 60)

    # 1. Ensure ClamAV is running
    print("[1/4] Checking Antivirus Engine (ClamAV)...", end=" ")
    clam_ok = analyzer.ensure_clamd_running()
    if clam_ok:
        print("ONLINE [OK]")
    else:
        print("OFFLINE (Fallback heuristics active)")

    # 2. Check Ollama AI Triage Model
    print("[2/4] Checking Local AI Specialist (qwen2.5-coder:1.5b)...", end=" ")
    try:
        analyzer.llm.invoke("ping")
        print("ONLINE [OK]")
    except Exception:
        print("OFFLINE (Check if Ollama is running)")

    # 3. Generate or Load Local SSL/TLS Certificates
    print("[3/4] Initializing Local SSL/TLS Certificates...", end=" ")
    cert_path, key_path, local_ip = cert_manager.generate_self_signed_cert()
    print("READY [OK]")

    # 4. Display Network Access URLs and Terminal QR Code
    portal_url = f"https://{local_ip}:8000"
    local_url = "https://localhost:8000"

    print("\n" + "-" * 60)
    print("  FORTRESS IS ARMED & READY")
    print(f"  > Connect your phone on the same Wi-Fi to:")
    print(f"    {portal_url}")
    print(f"  > Or access locally on this laptop:")
    print(f"    {local_url}")
    print("-" * 60)
    print("\nScan this QR code with your phone camera to open the portal:\n")

    try:
        qr = qrcode.QRCode(box_size=1, border=2)
        qr.add_data(portal_url)
        qr.print_ascii(invert=True)
    except Exception:
        pass

    print("\nNote: Because this connection is 100% private and runs locally,")
    print("your phone browser will display a standard self-signed certificate notice.")
    print("Tap 'Advanced' -> 'Proceed to site' once to enter.\n")
    print("Press Ctrl+C to safely shut down the gateway.")
    print("=" * 60 + "\n")

    # Start HTTPS server
    uvicorn.run(
        "backend:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile=key_path,
        ssl_certfile=cert_path,
        log_level="info"
    )

if __name__ == "__main__":
    main()

