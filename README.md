# ETIPOS: Encrypted Tunnels In Phones Obviously Secured

---

## Overview

ETIPOS is an air-gapped secure file transfer pipeline designed for high-security environments. It mitigates the privacy and grid/energy footprint risks of centralized cloud data centers by conducting in-flight static decompilation, local SLM threat scoring (Ollama / CyberSecEval), and encryption across a strictly local 3-node topology.
<img width="850" height="487" alt="image" src="https://github.com/user-attachments/assets/772c3f3c-d624-4bb7-8646-3de66d0f9335" />

---
## Quickstart

### 1. Launch Gateway Security Console (Node 2)
```bash
python run.py
```
Scan the QR code which will open a browser at `http://localhost:8000` to interact with the real-time Gateway Security Console.
- Drag and drop files.
