# COMP3334 Windows Runbook (GUI Demo + Error Handling)

This guide is for Windows users to deploy and run this project from a clean machine, and to verify key requirements from `Project [Rev. 1].pdf`.

## 1. Prerequisites (Windows 11)

1. Install Python 3.12 (recommended).
2. Open PowerShell in project root:
   - `C:\Users\user\Downloads\COMP3334-Computer-System-Security`
3. Create virtual environment:
   - `py -3.12 -m venv .venv`
4. Install dependencies:
   - `.\.venv\Scripts\python.exe -m pip install -U pip setuptools wheel`
   - `.\.venv\Scripts\python.exe -m pip install --no-cache-dir -r requirements.txt`

Notes:
- If your system blocks `Activate.ps1`, you can still run everything with `.\.venv\Scripts\python.exe` directly.
- Avoid Python 3.14 for this project to reduce package compatibility issues.

## 2. Start Server (local HTTP demo mode)

Open Terminal A:

```powershell
cd "C:\Users\user\Downloads\COMP3334-Computer-System-Security"
$env:IM_ALLOW_INSECURE_HTTP="1"
$env:IM_RELOAD="0"
.\.venv\Scripts\python.exe run_server.py
```

Expected output:
- `WARNING: Starting insecure HTTP server on http://127.0.0.1:8000`
- `Uvicorn running on http://127.0.0.1:8000`

Keep Terminal A running.

## 3. Start Two GUI Clients (Alice and Bob)

Use separate folders to isolate local client state.

Open Terminal B (Alice):

```powershell
cd "C:\Users\user\Downloads\COMP3334-Computer-System-Security\alice"
$env:IM_SERVER="http://127.0.0.1:8000"
& "..\.venv\Scripts\python.exe" "..\gui_client.py"
```

Open Terminal C (Bob):

```powershell
cd "C:\Users\user\Downloads\COMP3334-Computer-System-Security\bob"
$env:IM_SERVER="http://127.0.0.1:8000"
& "..\.venv\Scripts\python.exe" "..\gui_client.py"
```

In each GUI window:
1. Set `Server` to `http://127.0.0.1:8000`
2. Click `Apply`

## 4. OTP (6-digit) for GUI Login

This project uses TOTP. GUI registration returns `OTP secret` and `OTP URI`.

### GUI-only method (recommended)
1. Click `Register` in GUI.
2. Copy `OTP secret` from output.
3. Add account in Google/Microsoft Authenticator manually using that secret.
4. Use the generated 6-digit code in GUI `Login`.

### PowerShell fallback (if no phone app)
```powershell
.\.venv\Scripts\python.exe -c "import pyotp; print(pyotp.TOTP('YOUR_OTP_SECRET').now())"
```

Important:
- `OTP secret` must be complete and exact (no spaces/newline).
- If you see `Incorrect padding`, your secret is malformed or truncated.

## 5. GUI Demo Flow (end-to-end)

1. Alice: `Register` -> `Login`
2. Bob: `Register` -> `Login`
3. Alice: `Add Friend` (bob)
4. Bob: `Friend Requests` -> `Respond Request` (`accept`)
5. Alice: `Sync Key` (bob) -> `Verify Peer` (bob) -> `Trust Status`
6. Bob: `Sync Key` (alice) -> `Verify Peer` (alice) -> `Trust Status`
7. Alice: `Send Msg` to bob
8. Bob: `Pull Msgs`
9. Bob: `Send Msg` to alice
10. Alice: `Pull Msgs`

Optional security demo:
- Bob: `Block User` (alice)
- Alice: `Send Msg` to bob and verify failure (`403`, blocked).

## 6. Common Errors and Fixes

### Error A: `Activate.ps1` blocked by execution policy
Symptom:
- `PSSecurityException` / script execution disabled.

Fix options:
1. Temporary policy for current terminal:
   - `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
2. Or skip activation entirely:
   - Use `.\.venv\Scripts\python.exe ...` for all commands.

### Error B: `ModuleNotFoundError: requests` / `pyotp`
Cause:
- Using system Python instead of `.venv`.

Fix:
- Run with venv Python path explicitly, for example:
  - `.\.venv\Scripts\python.exe gui_client.py`
  - `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`

### Error C: `TLS is default. Missing cert.pem/key.pem`
Cause:
- `run_server.py` defaults to TLS.

Fix (local demo):
- Set `IM_ALLOW_INSECURE_HTTP=1`.

### Error D: `pydantic_core._pydantic_core` not found
Cause:
- Broken/mixed virtual environment wheels.

Fix:
1. Delete `.venv`
2. Recreate with Python 3.12
3. Reinstall dependencies with `--no-cache-dir`

### Error E: OTP command `NameError`
Cause:
- Secret not wrapped in quotes.

Fix:
```powershell
.\.venv\Scripts\python.exe -c "import pyotp; print(pyotp.TOTP('YOUR_SECRET').now())"
```

### Error F: OTP `Incorrect padding`
Cause:
- Invalid or incomplete secret.

Fix:
- Re-copy `OTP secret` from GUI registration output or use `OTP URI` and extract `secret=...`.

## 7. Requirement Coverage Checklist (Project [Rev. 1])

Use this section during testing/report writing.

- `R1` Registration: GUI `Register`.
- `R2` Password + OTP login: GUI `Login` with 6-digit TOTP.
- `R3` Logout/session invalidation: GUI `Logout`.
- `R4` Per-device identity keypair: generated client-side (automatic on register).
- `R5` Fingerprint/verification UI: GUI `Sync Key`, `Verify Peer`, `Trust Status`.
- `R6` Key change detection: verify trust status behavior after key updates.
- `R7` Secure session establishment: implemented (X25519 + HKDF), validated by successful encrypted messaging.
- `R8` Encryption + AD binding: encrypted send/pull flow.
- `R9` Replay protection: duplicate/replay should be rejected by design.
- `R10` TTL policy: send message with TTL in GUI.
- `R11` Client deletion behavior: confirm expired content is no longer available in client flow.
- `R12` Server expiry cleanup: handled server-side (best effort).
- `R13` Friend request workflow: `Add Friend` -> `Respond Request`.
- `R14` Request lifecycle: view and respond/cancel requests in client flows.
- `R15` Blocking/removing: GUI `Block User`, `Remove Friend`.
- `R16` Anti-spam default: non-friends cannot send chat messages.
- `R17` Delivery states: `sent`, `delivered`.
- `R18` Delivered semantics: recipient pull + protected ack flow.
- `R19` Metadata disclosure statement: include in report.
- `R20` Offline ciphertext queue: send while recipient offline, then pull.
- `R21` Retention/cleanup: TTL and cleanup policy.
- `R22` Duplicate/replay robustness: verify with repeated pull/retry scenarios.
- `R23` Conversation list: GUI `Conversations`.
- `R24` Unread counters: verify unread changes through message flow.
- `R25` Paging/incremental loading: endpoints support `limit/offset`.

Reference:
- See `REQUIREMENT_MAP.md` for implementation mapping details.

## 8. Evidence to Capture for Report

Recommended screenshots/log evidence:
1. Registration output with OTP setup info.
2. Successful OTP login.
3. Friend request send + accept.
4. Sync key + verified trust status.
5. Send/pull encrypted message.
6. Blocked message attempt (`403`).
7. Conversations/unread counters.
8. Offline queue behavior (recipient offline then pull).

## 9. Submission Packaging Reminder

Follow the required structure from project brief:

```text
TeamID/
  code/
  report.pdf
  video.mp4
```

Zip as:
- `TeamID.zip`

