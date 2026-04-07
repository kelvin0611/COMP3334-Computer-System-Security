# COMP3334 Secure IM Project (Baseline)

This repository contains a baseline implementation that follows the COMP3334 project brief:
- 1:1 E2EE private messaging
- Timed self-destruct (TTL)
- Registration + password + OTP login
- Friend request workflow
- Offline ciphertext queue (store-and-forward)
- Delivery states (`sent`, `delivered`) and acknowledgements
- Conversation list and unread counters

## 1) Environment setup (Windows 11 / Ubuntu / macOS)

1. Install Python 3.10+.
2. Open terminal in this folder.
3. Create virtual environment:
   - macOS/Linux: `python3 -m venv .venv && source .venv/bin/activate`
   - Windows (PowerShell): `py -m venv .venv; .\.venv\Scripts\Activate.ps1`
4. Install dependencies:
   - `pip install -r requirements.txt`
5. (Optional fallback) Protect local private key at rest with passphrase:
   - macOS/Linux: `export IM_STATE_PASSPHRASE="your-strong-passphrase"`
   - Windows (PowerShell): `$env:IM_STATE_PASSPHRASE="your-strong-passphrase"`
6. OS keychain-backed storage is preferred and used when `keyring` is available.

## 2) Run server (TLS-first default)

```bash
python run_server.py
```

`run_server.py` behavior:
- if `cert.pem` + `key.pem` exist, starts HTTPS on `8443` by default
- otherwise refuses to start unless `IM_ALLOW_INSECURE_HTTP=1` is set

For local HTTP-only testing:

```bash
IM_ALLOW_INSECURE_HTTP=1 python run_server.py
```

SQLite database `im.db` is auto-created.

## 3) Run client commands

Use another terminal:

```bash
python client.py register --username alice --password "StrongPass123"
python client.py login --username alice --password "StrongPass123" --otp 123456
```

Then for another user (in separate folder copy or by changing `client_state.json` between users):

```bash
python client.py register --username bob --password "StrongPass123"
python client.py login --username bob --password "StrongPass123" --otp 123456
```

Friend and messaging flow:

```bash
python client.py add-friend --user bob
python client.py friend-requests --limit 20 --offset 0
python client.py accept --id 1
python client.py sync-key --user bob
python client.py trust-status --user bob
python client.py verify-peer --user bob
python client.py key-storage-status
python client.py migrate-local-key-keychain
python client.py encrypt-local-key
python client.py send --to bob --text "hello" --ttl 60
python client.py pull --limit 20 --offset 0
python client.py conversations --limit 20 --offset 0
python client.py logout
```

## 3b) Simple Terminal UI (recommended for testing)

This wraps `client.py` in an interactive menu so you can test faster.

In a user folder (e.g., `alice/` or `bob/`) run:

```bash
IM_SERVER="http://127.0.0.1:8000" python ../ui_client.py
```

For TLS-first server:
```bash
IM_SERVER="https://127.0.0.1:8443" python ../ui_client.py
```

## 4) Security notes

- E2EE key agreement: X25519 + HKDF-SHA256
- Message protection: AES-256-GCM
- AD binds sender/receiver/conversation/counter/TTL
- Replay resistance: monotonic per-peer message counter check
- Strict key verification policy: peer keys must be explicitly verified before sending
- Delivery ACK is returned as E2EE encrypted ACK message (`ack-e2ee`) from recipient client
- Password storage: PBKDF2-SHA256 via Passlib
- OTP: TOTP (RFC 6238 style) via PyOTP
- Server stores ciphertext only, not plaintext keys

## 5) Important limitations in this baseline

- JWT secret is hardcoded placeholder; replace for production.
- TLS-first startup is implemented, but cert management/proxy hardening is still your deployment task.
- Local key storage supports OS keychain (preferred) and passphrase-encrypted fallback.
- CLI only (acceptable by brief), not GUI.

## 6) Suggested deliverable structure for submission

Create:

```text
TeamID/
  code/   (this project)
  report.pdf
  video.mp4
```

Zip as `TeamID.zip`.

## 7) Report drafting support

Use `REPORT_TEMPLATE.md` as your report skeleton. It already includes the required sections and two security test case templates.
Use `FINAL_SUBMISSION_CHECKLIST.md` before packaging `TeamID.zip`.

## 8) TLS deployment guide (required for final submission)

Use one of these approaches:

1. **Direct Uvicorn TLS (simple demo)**
   - Generate cert and key (development only):
     - `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365`
   - Run server with TLS:
     - `uvicorn server:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem`
   - Set client endpoint:
     - `export IM_SERVER=https://<host>:8443`

2. **Reverse proxy TLS (recommended)**
   - Put Nginx/Caddy in front of Uvicorn.
   - Terminate TLS at proxy with managed certificates (e.g., Let's Encrypt).
   - Forward to internal `http://127.0.0.1:8000`.
   - Enforce HTTPS redirect and modern TLS settings.

For your report, include:
- certificate strategy (self-signed/dev vs CA-issued/prod),
- where TLS is terminated,
- and how clients verify server certificates.

