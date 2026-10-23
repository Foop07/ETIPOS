import os
import sys
import uvicorn
import qrcode
import cert_manager
import analyzer
import subprocess
import signal

# Ensure terminal can print UTF-8 characters and QR blocks on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# P2P Configuration
P2P_EXPIRY_SECONDS = int(os.getenv("P2P_EXPIRY_SECONDS", "300"))  # Default 5 minutes for testing
TRACKER_PORT = int(os.getenv("TRACKER_PORT", "8001"))
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))


def start_bun_tracker():
    """Start the Bun P2P tracker server"""
    bun_path = os.path.join(os.path.dirname(__file__), "p2p-relay", "node_modules", ".bin", "bun")
    
    # Try different possible bun locations
    possible_bun_paths = [
        bun_path,
        os.path.expanduser("~/.bun/bin/bun.exe"),
        "bun",
        "C:\\Users\\jaini\\.bun\\bin\\bun.exe"
    ]
    
    bun_executable = None
    for path in possible_bun_paths:
        if os.path.exists(path):
            bun_executable = path
            break
        # Check if it's in PATH
        try:
            subprocess.run([path, "--version"], capture_output=True, timeout=2)
            bun_executable = path
            break
        except:
            continue
    
    if not bun_executable:
        print("WARNING: Bun not found, P2P tracker will not start")
        return None
    
    tracker_script = os.path.join(os.path.dirname(__file__), "p2p-relay", "src", "index.ts")
    
    if not os.path.exists(tracker_script):
        print("WARNING: P2P tracker script not found")
        return None
    
    try:
        # Start Bun tracker in background
        process = subprocess.Popen(
            [bun_executable, tracker_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "p2p-relay"),
            env={**os.environ, "TRACKER_PORT": str(TRACKER_PORT)},
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )
        print(f"    P2P Tracker (Bun): Started on port {TRACKER_PORT}")
        return process
    except Exception as e:
        print(f"WARNING: Failed to start P2P tracker: {e}")
        return None


def main():
    print("=" * 60)
    print("  ETIPOS SECURE LOCAL WIRELESS RELAY - FORTRESS GATEWAY")
    print("=" * 60)
    
    # Set environment variables for backend
    os.environ["P2P_EXPIRY_SECONDS"] = str(P2P_EXPIRY_SECONDS)
    os.environ["TRACKER_PORT"] = str(TRACKER_PORT)
    
    # 1. Ensure ClamAV is running
    print("[1/5] Checking Antivirus Engine (ClamAV)...", end=" ")
    clam_ok = analyzer.ensure_clamd_running()
    if clam_ok:
        print("ONLINE [OK]")
    else:
        print("OFFLINE (Fallback heuristics active)")
    
    # 2. Check Ollama AI Triage Model
    print("[2/5] Checking Local AI Specialist (qwen2.5-coder:1.5b)...", end=" ")
    try:
        analyzer.llm.invoke("ping")
        print("ONLINE [OK]")
    except Exception:
        print("OFFLINE (Check if Ollama is running)")
    
    # 3. Generate or Load Local SSL/TLS Certificates
    print("[3/5] Initializing Local SSL/TLS Certificates...", end=" ")
    cert_path, key_path, local_ip = cert_manager.generate_self_signed_cert()
    print("READY [OK]")
    
    # 4. Start P2P Tracker (Bun)
    print("[4/5] Starting P2P Relay Server (WebTorrent Tracker)...", end=" ")
    tracker_process = start_bun_tracker()
    if tracker_process:
        print(f"ONLINE [OK] (ws://{local_ip}:{TRACKER_PORT})")
    else:
        print("OFFLINE (P2P transfers will not work)")
    
    # 5. Display Network Access URLs
    portal_url = f"https://{local_ip}:{SERVER_PORT}"
    local_url = f"https://localhost:{SERVER_PORT}"
    
    print("\n" + "-" * 60)
    print("  FORTRESS IS ARMED & READY")
    print(f"  > Connect your phone on the same Wi-Fi to:")
    print(f"    {portal_url}")
    print(f"  > Or access locally on this laptop:")
    print(f"    {local_url}")
    
    if tracker_process:
        print(f"  > P2P Tracker available at:")
        print(f"    ws://{local_ip}:{TRACKER_PORT}")
        print(f"  > HTTP Tracker at:")
        print(f"    http://{local_ip}:{TRACKER_PORT}/announce")
    
    print("-" * 60)
    print("\nScan this QR code with your phone camera to open the portal:\n")
    
    try:
        qr = qrcode.QRCode(box_size=1, border=2)
        qr.add_data(portal_url)
        qr.print_ascii(invert=True)
    except Exception:
        pass
    
    print("\n" + "-" * 60)
    print("  P2P TRANSFER FEATURES")
    print(f"  > P2P Expiry: {P2P_EXPIRY_SECONDS} seconds ({P2P_EXPIRY_SECONDS // 60} minutes)")
    print(f"  > Tracker Port: {TRACKER_PORT}")
    print(f"  > Email: Configure SMTP credentials to enable")
    print("-" * 60)
    print("\nNote: Because this connection is 100% private and runs locally,")
    print("your phone browser will display a standard self-signed certificate notice.")
    print("Tap 'Advanced' -> 'Proceed to site' once to enter.\n")
    print("Press Ctrl+C to safely shut down the gateway.")
    print("=" * 60 + "\n")
    
    # Setup graceful shutdown
    def shutdown_handler(signum, frame):
        print("\n🛑 Shutting down ETIPOS...")
        
        # Stop P2P tracker
        if tracker_process:
            try:
                tracker_process.terminate()
                tracker_process.wait(timeout=5)
            except:
                tracker_process.kill()
        
        print("✅ All services stopped. Goodbye!")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    # Start HTTPS server
    uvicorn.run(
        "backend:app",
        host="0.0.0.0",
        port=SERVER_PORT,
        ssl_keyfile=key_path,
        ssl_certfile=cert_path,
        log_level="info"
    )


if __name__ == "__main__":
    main()