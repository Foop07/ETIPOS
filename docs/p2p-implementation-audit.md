# ETIPOS P2P Implementation Audit

**Audit date:** 2026-10-23  
**Compared against:** `C:\Users\jaini\.opencode\plan\2026-10-23-p2p-file-transfer.md`  
**Audit scope:** Review of plan tasks 1–8, current source, and tests run during this audit. This is an implementation review, not a claim that transfers have been exercised across real devices or networks.

## Executive summary

The repository contains artifacts for all eight planned tasks, but the feature is **not ready for end-to-end use**. Python API tests and the Bun tracker’s basic lifecycle tests pass. TypeScript typechecking passes. The browser tests have not run successfully, SMTP delivery has not been tested against a real server, and there is no verified browser-to-browser transfer.

Most importantly, the current code does not create a BitTorrent torrent. The backend hashes raw file bytes and labels that SHA-1 as a BitTorrent info hash; that is not the info hash of a torrent metadata dictionary. The Bun tracker also does not implement the WebTorrent tracker protocol. Therefore the generated magnet URI and tracker cannot reliably connect the WebTorrent browser peers. No TURN relay node is implemented, so transfers across NATs/firewalls are not assured.

**Bottom line:** file scanning endpoints, email-message construction, static PWA assets, and basic tracker server startup have partial unit-level evidence. Real P2P transfer, cross-distance relay, direct email delivery, Android share flow, mobile PWA installability, and the 2 GB memory-safe path remain unverified or incomplete.

## Verification performed

| Check | Result | Evidence / limitation |
|---|---|---|
| `python -m pytest -q` | **PASS** | 10 passed; 4 deprecation warnings (PyPDF2, `pkg_resources`, FastAPI `on_event`). These tests are mocks/static assertions; they do not exercise SMTP, actual network startup, or P2P. |
| `bun run test` in `p2p-relay/` | **PASS** | 2 tracker server lifecycle tests passed. No announce interoperability or peer exchange test. |
| `bun run typecheck` in `p2p-relay/` | **PASS** | `bun check`: no type errors in 8 files. |
| `bun run test:e2e` in `p2p-relay/` | **BLOCKED** | Playwright fails at startup with Node ESM loader error: unsupported `bun:` protocol. Browser tests were not executed. |
| Full P2P transfer from sender to receiver | **NOT VERIFIED / EXPECTED NOT TO WORK** | No proper torrent metadata creation, incompatible custom tracker protocol, and no browser-to-browser test. |
| Real SMTP send | **NOT RUN** | Test mocks SMTP only; no SMTP credentials or server delivery verified. |
| Android/iOS PWA install and share target | **NOT RUN** | Manifest and service worker files exist, but installed-device behavior was not tested. |
| Existing local transfer baseline | **NOT FULLY VERIFIED** | Existing `/transfer` and `/download/{pin}` implementation was not intentionally changed in P2P tasks, but this audit did not run a full local two-device transfer. |

The root-level `pytest` run had previously timed out once; a fresh full run during this audit completed successfully.

## Plan-by-plan assessment

### Task 1 — Email Service Module: **Implemented; unit-tested only**

- `email_service.py` builds a multipart plain-text/HTML message and sends through SMTP with STARTTLS.
- `test_email_service.py` uses a fake SMTP server; it confirms message content, not external delivery.
- No configurable public transfer URL is used in the email. The email includes a magnet URI and PIN, but does not provide a tested browser receiver link.
- Message fields interpolate filename, PIN, and URL into HTML without HTML escaping. Treat filenames as untrusted; escape them before HTML output.
- SMTP credentials are read at import time. Missing credentials do not fail early; unauthenticated SMTP may be attempted.

### Task 2 — P2P FastAPI Endpoints: **Present; partial tests; P2P metadata invalid**

- `backend.py` has `POST /transfer/p2p`, `POST /transfer/email`, and `GET /transfer/p2p/{pin}`.
- Endpoint tests mock triage and email. They verify status/response structure, not torrent interoperability or mail delivery.
- Scan approval is checked via `report["status"] == "APPROVED"` after the audit change. Malware scanner implementation itself was not modified in these feature commits.
- The endpoint reads the entire upload into RAM before checking the 2 GB limit. This is not a safe streaming/size-enforcement implementation for near-2-GB uploads and can exhaust memory.
- `MAX_P2P_FILE_BYTES` rejects lengths `>= 2 GiB`; that is consistent with “less than 2 GB” only if GB means GiB. Clarify decimal vs binary limit.
- The raw-file SHA-1 is not a BitTorrent info hash. A proper torrent must be created from bencoded torrent metadata and include piece hashes; simply returning a magnet cannot seed the upload as a WebTorrent torrent.
- PIN generation overwrites a preexisting entry on collision; the plan’s PIN collision review item is not addressed. Six digits alone are not an authorization-strength guarantee.
- Vault contents and torrent metadata exist only in process memory, so restart loses transfers. Expiry is opportunistic cleanup on endpoint calls, not a background cleanup task.
- Email endpoint accepts an unvalidated dictionary, returns HTTP 200 with `sent: false` on send failure, and does not rate-limit requests.

### Task 3 — Bun/TypeScript Tracker & Signaling: **Server skeleton exists; not a compatible WebTorrent tracker**

- `p2p-relay/src/tracker.ts` starts Bun HTTP/WebSocket server and offers `/stats`; its lifecycle tests pass.
- `/announce` returns JSON objects with peer IDs, but no standard HTTP tracker peer representation or proper WebTorrent WebSocket tracker message protocol is implemented. HTTP announces also do not register peers in the swarm.
- The browser pages announce using a custom WebSocket URL, but the tracker expects custom JSON (`action: "announce"`, `info_hash`, `peer_id`) rather than WebTorrent’s tracker protocol.
- The `ws` library dependency and `src/signaling.ts` are not used by the active `src/index.ts`/tracker implementation. That signaling module is a separate, unfinished protocol.
- The initial `bittorrent-tracker` package was removed after native dependency load failure; the current custom server is not a protocol-equivalent replacement.
- The plan described optional relay/TURN behavior. No TURN server or relay node is implemented.

### Task 4 — P2P Send Page: **UI exists; not verified and seeding is incorrect**

- `static/p2p-send.html` has upload, progress/error UI, PIN/magnet display, and email fields.
- It uses browser `fetch` without upload progress reporting. The “progress” is scan status, not upload byte progress.
- It loads WebTorrent from a CDN, which conflicts with strict local-only/offline behavior and may be blocked by the service worker/security policy.
- `wtClient.seed(selectedFile, { announce: [URL extracted from magnet] })` creates a new torrent independently, but the returned magnet from the backend was made from a raw file hash. The sender’s actual WebTorrent torrent info hash will differ; receiver will not find this seeded torrent.
- The page does not destroy the seeding client on normal page close and does not protect against the sender closing the page. P2P availability depends on sender staying online.
- The link in the email is a magnet URI; it does not navigate into the receiver page with PIN as envisioned in the plan.
- Playwright tests expect `http://localhost:5000`, but `run.py` defaults to HTTPS port 8000. Tests also use `p2p-relay/test` and were not executable under the current Playwright runner configuration.

### Task 5 — P2P Receive Page: **UI exists; download interoperability not verified**

- `static/p2p-receive.html` supports PIN query parameter, metadata lookup, progress UI, and a WebTorrent client call.
- It uses the raw-hash magnet and custom tracker protocol mismatch described above, so a transfer is not demonstrated to work.
- It assumes `torrent.files[0]`; multi-file torrents and file selection are not handled (though current intent is a single file).
- `getBlobURL` for files near 2 GB is likely to require very large in-memory browser blobs; this does not meet the plan’s memory-safe large-file concern and browser storage/download limits vary by device.
- The page reports seeding once progress is nonzero, before the download is complete; that message overstates behavior.
- There is no timeout/error state for “no peers found,” tracker unavailability, or NAT traversal failure.

### Task 6 — PWA Manifest & Service Worker: **Files exist; Android share flow is incomplete**

- `static/manifest.json`, `static/sw.js`, and 192/512 PNG icons exist; links/registration were added to HTML pages.
- Manifest declares a `share_target` POST to `/static/p2p-send.html`.
- The service worker’s first `fetch` handler immediately returns for all non-GET requests; a second handler intended to handle the share-target POST is therefore never registered with `respondWith`. The share target cannot be considered implemented.
- For the app pages under `/static/`, the service worker is registered at `/static/sw.js`; scope defaults to `/static/`. That scope can control those static pages, but does not control root routes.
- Cache install swallows `cache.addAll` failure, which can conceal incomplete/offline setup. A cached shell does not make API transfers available offline.
- `sw.js` and page scripts use CDN WebTorrent. Those third-party assets are not included in the precache list.
- iOS home-screen metadata exists, but PWA behavior on mobile browsers is not device-tested. PWA must be served from a secure context; the app uses self-signed TLS, which users must trust/accept and may not satisfy normal install criteria consistently.
- `create_icons.py` is checked in as an extra helper; generated icons exist.

### Task 7 — Configuration & Integration: **Partial; startup claims do not match effective runtime**

- `.env.example` documents SMTP, expiry, tracker, TURN, and port settings.
- `backend.py` reads `P2P_EXPIRY_SECONDS` once at import time; it now defaults to 60 seconds. The plan wanted production 3 days with a test override. Current default is test-like, not production-like.
- `run.py` launches FastAPI on port 8000 by default and starts Bun in a subprocess. It chooses Bun paths using a hard-coded user path as one fallback, and captures stdout/stderr without draining them, which can block the child if buffers fill.
- `run.py` probes ports/configuration via environment but the existing integration test was replaced with static checks, so “both servers start” is not verified.
- Receiver URL construction in `backend.py` uses hard-coded `:5000`, while `run.py` defaults to HTTPS `:8000`; returned receiver URL is wrong for the default launch configuration.
- The tracker URL is `ws://` even though the app runs over HTTPS. Browsers generally block insecure WebSocket connections (`ws://`) from secure pages; the client should use `wss://` with a certificate-valid tracker or same-origin secure reverse proxy.
- Local-only networking and arbitrary-distance transfer conflict unless both users can reach the sender/tracker or an internet-accessible rendezvous/TURN relay exists. The current code cannot promise “no matter the distance” while also being strictly local-only.
- `.env.example` is documentation only; no `.env` loader is wired (environment variables must be set in the process environment).

### Task 8 — E2E Testing & Polish: **Not complete as planned**

- Python tests validate endpoint behavior with mocked scan/mail and PWA file contents.
- Bun tests cover only server construction/close, not actual announces, swarms, signaling, or peer exchange.
- Playwright test files exist but `bun test` initially tried to load them with the Bun test runner and failed. A separate script was added, but executing it currently fails with Node’s `bun:` ESM protocol error. No browser tests passed.
- The plan’s manual checks (two phones, different networks, SMTP delivery, PWA installation, Android share picker, large-file test) have not been performed.
- The full `python -m pytest -q` suite passed in this audit, but its integration file no longer starts both servers. It should not be interpreted as a multi-service E2E test.

## Foundation preservation

The feature work did not intentionally edit malware scanning logic in `analyzer.py`. Existing `/transfer` and `/download/{pin}` handlers remain present in `backend.py`. However, the full unchanged local-transfer flow was not independently verified in this audit. There is a consequential shared behavior change: `EXPIRATION_SECONDS` now comes from `P2P_EXPIRY_SECONDS` and defaults to 60 seconds, affecting the existing local vault too, not just P2P. In addition, memory usage and cleanup behavior of the shared vault remain relevant to both paths.

## Risk-ranked remaining work

### Blockers before claiming P2P works

1. Use a real WebTorrent-compatible tracker implementation or correctly implement its wire protocol and prove interop with the exact browser WebTorrent client version.
2. Create one actual torrent from the file (including piece hashes/info dictionary); return that torrent’s `magnetURI` and seed the same torrent instance that produced it.
3. Add protocol integration tests with two WebTorrent clients that announce, discover each other, transfer bytes, and verify a checksum.
4. Decide how recipients reach senders across networks. Add a real TURN relay or document/limit the topology; STUN alone is not a data relay and cannot guarantee traversal.
5. Use HTTPS/WSS consistently and generate a receiver URL from configured public/base URL and actual server port.

### Security/reliability before broader testing

6. Enforce upload limits while streaming, before buffering entire requests; use file-backed temporary storage for large uploads and validate memory behavior.
7. Keep local and P2P expiries distinct/configurable; prevent PIN collisions and avoid exposing a predictable short PIN as the sole authorization factor.
8. Fix share target POST handling and verify actual Android share flow; validate static service-worker cache installation and offline behavior.
9. Escape email HTML and input filenames; configure SMTP TLS/auth behavior explicitly and surface delivery failures as non-2xx API errors.
10. Make integration tests start/stop both processes with deterministic ports and capture/drain logs safely; run browser tests in a normal Node Playwright environment.

## Recommended status label

**Prototype artifacts implemented; end-to-end P2P transfer not functional/verified.** The foundation scanning and local transfer are retained in source but should be re-run through an explicit regression test before merging or presenting this as a working release.
