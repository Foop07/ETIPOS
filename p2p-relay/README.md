# ETIPOS WebTorrent POC

This service uses the official `bittorrent-tracker` WebSocket tracker protocol,
`create-torrent` for real BitTorrent metadata, and WebTorrent 2.8.4 for the
browser client and Node seeder. Dependencies are pinned in `package.json` and
`bun.lock`.

## Setup and checks

```sh
bun install
bun run build:browser
bun run typecheck
bun run test
```

Run the integrated service with `python run.py`. The receiver browser requires
HTTPS and a trusted local certificate. The official tracker currently listens
on plain WS; browsers block this as mixed content from the HTTPS receiver page.
Configure a WSS reverse proxy and set `TRACKER_URL=wss://<trusted-host>/<path>`
before treating the browser flow as testable. `run.py` does not configure this
proxy automatically. The runner's own tracker listens on `ws://`; P2P uploads
from its TLS-enabled server deliberately return HTTP 503 until a trusted WSS
tracker URL is configured, rather than returning a magnet browsers cannot use.
Allow both FastAPI and tracker ports through the host firewall.

## Acceptance gate

Automated metadata/tracker checks do not demonstrate end-user usability. The
POC is not considered usable until a sender laptop and a separate recipient
phone on the same Wi-Fi complete a real transfer and the recipient's SHA-256
matches the sender's. Cross-network support is not claimed or tested. TURN is
not included, and P2P files are limited to less than 2 GiB.
