import secrets
import os
import sys
import uvicorn
import qrcode
import cert_manager
import analyzer
import subprocess
import signal
import shutil
import threading
import re

# cloudflared tunnel --protocol http2 --url https://localhost:8000 --no-tls-verify

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
cloudflared_public_url = None
cloudflared_url_event = threading.Event()


def auto_build_typescript():
    """Ensure TypeScript sources in src/ are compiled to static/."""
    npm_path = shutil.which("npm") or shutil.which("npm.cmd")
    if not npm_path:
        return
    src_dir = os.path.join(os.path.dirname(__file__), "src")
    if not os.path.exists(src_dir):
        return

    print("    [TS] Compiling TypeScript assets...", end=" ")
    try:
        res = subprocess.run(
            [npm_path, "run", "build"],
            cwd=os.path.dirname(__file__),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=sys.platform == "win32"
        )
        if res.returncode == 0:
            print("OK")
        else:
            print("WARNING (tsc warning/error)")
    except Exception as e:
        print(f"Skipped ({e})")


def start_cloudflared_tunnel(local_port: int):
    """
    Auto-launch cloudflared tunnel in the background.

    Quick Tunnel mode (default, no account needed):
        cloudflared tunnel --protocol http2 --url https://localhost:<port> --no-tls-verify
        URL is random each launch (e.g. abc123.trycloudflare.com).

    Named Tunnel mode (set CLOUDFLARE_TUNNEL_NAME in .env, permanent URL):
        cloudflared tunnel run --url https://localhost:<port> <name>
        Requires: cloudflared tunnel login  +  cloudflared tunnel create <name>
    """
    global cloudflared_public_url
    cf_path = shutil.which("cloudflared")
    if not cf_path:
        print("    Cloudflare Tunnel: 'cloudflared' not found on PATH. Remote access disabled.")
        return None

    tunnel_token = os.getenv("CLOUDFLARE_TUNNEL_TOKEN", "").strip()
    tunnel_name = os.getenv("CLOUDFLARE_TUNNEL_NAME", "").strip()
    public_url_env = os.getenv("PUBLIC_TUNNEL_URL", "").strip()

    if tunnel_token:
        # Dashboard-managed named tunnel using Token (No cert.pem needed!)
        cmd = [
            cf_path, "tunnel",
            "run",
            "--token", tunnel_token
        ]
        if public_url_env:
            cloudflared_public_url = public_url_env
            os.environ["CLOUDFLARED_URL"] = cloudflared_public_url
            cloudflared_url_event.set()
    elif tunnel_name:
        # CLI-created named tunnel using cert.pem
        cmd = [
            cf_path, "tunnel",
            "--protocol", "http2",
            "--no-tls-verify",
            "run",
            "--url", f"https://localhost:{local_port}",
            tunnel_name
        ]
    else:
        # Quick tunnel — random URL, works with zero setup
        cmd = [
            cf_path, "tunnel",
            "--protocol", "http2",
            "--url", f"https://localhost:{local_port}",
            "--no-tls-verify"
        ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )

        def monitor_tunnel_output(pipe):
            global cloudflared_public_url
            for line in iter(pipe.readline, ""):
                if not line:
                    break
                match = re.search(r"https://[a-zA-Z0-9-]+\.(trycloudflare\.com|cfargotunnel\.com)", line)
                if match and not cloudflared_public_url:
                    cloudflared_public_url = match.group(0)
                    os.environ["CLOUDFLARED_URL"] = cloudflared_public_url
                    cloudflared_url_event.set()
                    label = "PERMANENT" if (tunnel_name or tunnel_token) else "TEMPORARY"
                    print(f"\n    ⚡ CLOUDFLARE TUNNEL ONLINE [{label}]: {cloudflared_public_url}\n")

            # In token mode, print confirmation when tunnel connects to edge
            if tunnel_token and cloudflared_public_url:
                print(f"\n    ⚡ CLOUDFLARE TUNNEL ONLINE [PERMANENT]: {cloudflared_public_url}\n")

        t_err = threading.Thread(target=monitor_tunnel_output, args=(process.stderr,), daemon=True)
        t_out = threading.Thread(target=monitor_tunnel_output, args=(process.stdout,), daemon=True)
        t_err.start()
        t_out.start()

        return process
    except Exception as e:
        print(f"    WARNING: Failed to start cloudflared tunnel: {e}")
        return None


def start_bun_tracker():
    """Start the official WebTorrent-compatible tracker server."""
    node_path = shutil.which("node")
    if not node_path:
        print("WARNING: Node.js not found, P2P tracker will not start")
        return None
    
    tracker_script = os.path.join(os.path.dirname(__file__), "p2p-relay", "src", "index.ts")
    
    if not os.path.exists(tracker_script):
        print("WARNING: P2P tracker script not found")
        return None
    
    try:
        # Start the Node-compatible official tracker package in background.
        process = subprocess.Popen(
            [node_path, "--import", "./scripts/node-loader.mjs", "src/index.ts"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "p2p-relay"),
            env={**os.environ, "TRACKER_PORT": str(TRACKER_PORT)},
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )
        print(f"    P2P Tracker (Node): Started on port {TRACKER_PORT}")
        return process
    except Exception as e:
        print(f"WARNING: Failed to start P2P tracker: {e}")
        return None


def main():
    print("=" * 60)
    print("  ETIPOS SECURE LOCAL WIRELESS RELAY - FORTRESS GATEWAY")
    print("=" * 60)
    
    # 0. Compile TypeScript if available
    auto_build_typescript()

    # Set environment variables for backend
    os.environ["P2P_EXPIRY_SECONDS"] = str(P2P_EXPIRY_SECONDS)
    os.environ["TRACKER_PORT"] = str(TRACKER_PORT)

    # Generate random 6-digit access OTP for the session domain
    session_otp = f"{secrets.randbelow(900000) + 100000}"
    os.environ["ETIPOS_ACCESS_OTP"] = session_otp
    
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
    os.environ["TLS_CERT"] = cert_path
    os.environ["TLS_KEY"] = key_path
    print("READY [OK]")
    
    # 4. Start P2P Tracker (Bun/Node)
    print("[4/5] Starting P2P Relay Server (WebTorrent Tracker)...", end=" ")
    tracker_process = start_bun_tracker()
    if tracker_process:
        print(f"ONLINE [OK] (ws://{local_ip}:{TRACKER_PORT})")
    else:
        print("OFFLINE (P2P transfers will not work)")
    
    # 5. Launch Cloudflared Tunnel (Token/Named = permanent PWA, Quick = temp)
    tunnel_token = os.getenv("CLOUDFLARE_TUNNEL_TOKEN", "").strip()
    tunnel_name = os.getenv("CLOUDFLARE_TUNNEL_NAME", "").strip()
    if tunnel_token:
        print("[5/5] Launching Cloudflare Dashboard Tunnel (via Token)...", end=" ")
    elif tunnel_name:
        print(f"[5/5] Launching Named Cloudflare Tunnel '{tunnel_name}'...", end=" ")
    else:
        print("[5/5] Launching Cloudflare Quick Tunnel (temp URL)...", end=" ")
    cloudflared_process = start_cloudflared_tunnel(SERVER_PORT)
    if cloudflared_process:
        if tunnel_token or tunnel_name:
            print("LAUNCHED [OK] — Permanent URL (PWA install is persistent)")
        else:
            print("LAUNCHED [OK] — Temporary URL (changes each launch)")
    else:
        print("SKIPPED (Local Wi-Fi Only)")

    # Display Network Access URLs
    portal_url = f"https://{local_ip}:{SERVER_PORT}"
    local_url = f"https://localhost:{SERVER_PORT}"

    # If cloudflared is running, wait a few seconds for the tunnel URL to resolve
    if cloudflared_process and not cloudflared_public_url:
        print("\n    ⏳ Waiting for Cloudflare tunnel URL to establish...", end=" ", flush=True)
        cloudflared_url_event.wait(timeout=6.0)
        if cloudflared_public_url:
            print("DONE")
        else:
            print("TIMEOUT (will fall back to local URL)")

    qr_target_url = cloudflared_public_url or portal_url

    print("\n" + "-" * 60)
    print("  FORTRESS IS ARMED & READY")
    print(f"  > Access OTP (Enter on screen):  *** {session_otp} ***")
    print(f"  > Connect your phone on the same Wi-Fi to:")
    print(f"    {portal_url}")
    print(f"  > Or access locally on this laptop:")
    print(f"    {local_url}")
    if cloudflared_public_url:
        print(f"  > Cloudflare Tunnel URL (QR Destination):")
        print(f"    {cloudflared_public_url}")
    else:
        print(f"  > Public Internet (Cloudflare Tunnel): Auto-populating once ready")
    
    if tracker_process:
        print(f"  > P2P Tracker available at:")
        print(f"    ws://{local_ip}:{TRACKER_PORT}")
    
    print("-" * 60)
    print(f"\nScan this QR code with your phone camera to open the portal ({qr_target_url}):\n")
    
    try:
        qr = qrcode.QRCode(box_size=1, border=2)
        qr.add_data(qr_target_url)
        qr.print_ascii(invert=True)
    except Exception:
        pass
    
    print("\n" + "-" * 60)
    print("  P2P TRANSFER FEATURES")
    print(f"  > P2P Expiry: {P2P_EXPIRY_SECONDS} seconds ({P2P_EXPIRY_SECONDS // 60} minutes)")
    print(f"  > Tracker Port: {TRACKER_PORT}")
    print(f"  > Email: Configure SMTP credentials to enable")
    print("-" * 60)
    print("\nNote: Browser P2P currently requires a separately configured WSS proxy; ws:// is blocked from HTTPS pages.")
    print("Press Ctrl+C to safely shut down the gateway.")
    print("=" * 60 + "\n")
    
    # Setup graceful shutdown
    def shutdown_handler(signum, frame):
        print("\n🛑 Shutting down ETIPOS...")
        
        # Stop Cloudflare tunnel
        if cloudflared_process:
            try:
                cloudflared_process.terminate()
                cloudflared_process.wait(timeout=3)
            except Exception:
                try:
                    cloudflared_process.kill()
                except Exception:
                    pass

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
