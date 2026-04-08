# COMP3334 Secure IM Project (Windows 11 Guide)

This repository includes the required deliverables:
- **All source code** for server and client: `server.py`, `run_server.py`, `client.py`, `gui_client.py`, `ui_client.py`
- **Database import file**: `im.db` (SQLite database at project root)
- **Step-by-step deployment and usage document**: this `README.md` (Windows 11 only)

---

## 1. Software installation on clean Windows 11

No pre-installed libraries are assumed.

1. Install **Python 3.12** (recommended) from:
   - [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
2. During Python installation, check:
   - `Add python.exe to PATH`
3. Open **PowerShell** and verify:

```powershell
python --version
```

If version is shown, proceed.

---

## 2. Project setup (Windows PowerShell)

Open PowerShell in project root:

```powershell
cd Path\COMP3334-Computer-System-Security
```

Create virtual environment:

```powershell
python -m venv .venv
```

Install dependencies:

```powershell
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
& ".\.venv\Scripts\python.exe" -m pip install --no-cache-dir -r requirements.txt
```

---

## 4. Start server (Windows PowerShell)

`run_server.py` is TLS-first by default. For local demo on Windows, run HTTP mode:

```powershell
cd Path\COMP3334-Computer-System-Security
Remove-Item -Recurse -Force ".venv"
python -m venv .venv
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
& ".\.venv\Scripts\python.exe" -m pip install --no-cache-dir -r requirements.txt
$env:IM_ALLOW_INSECURE_HTTP="1"
$env:IM_HTTP_PORT="8000"
& ".\.venv\Scripts\python.exe" "run_server.py"
```

Expected endpoint:
- `http://127.0.0.1:8000`

Keep this terminal running.

---

## 5. Start GUI clients (Alice and Bob on Windows)

Use two separate PowerShell windows.

Important path rule:
- If you are in project root (`...\COMP3334-Computer-System-Security`), use `.\.venv\...`
- If you are in `alice` / `bob` folder, use `..\ .venv\...` (parent folder virtual environment)

Quick test from project root (single GUI):

```powershell
cd "C:\Users\user\Downloads\COMP3334-Computer-System-Security"
$env:IM_SERVER="http://127.0.0.1:8000"
& ".\.venv\Scripts\python.exe" ".\gui_client.py"
```

### Alice window

```powershell
cd "C:\Users\user\Downloads\COMP3334-Computer-System-Security\alice"
$env:IM_SERVER="http://127.0.0.1:8000"
& "..\.venv\Scripts\python.exe" "..\gui_client.py"
```

### Bob window

```powershell
cd "C:\Users\user\Downloads\COMP3334-Computer-System-Security\bob"
$env:IM_SERVER="http://127.0.0.1:8000"
& "..\.venv\Scripts\python.exe" "..\gui_client.py"
```

---

## 6. Step-by-step usage flow

1. In Alice GUI: click `Register`.
2. In Bob GUI: click `Register`.
3. In Alice GUI: click `Login` (password + 6-digit OTP).
4. In Bob GUI: click `Login` (password + 6-digit OTP).
5. Alice: click `Add Friend`, input Bob username.
6. Bob: click `Friend Requests`, then `Respond Request` with `accept`.
7. Alice: `Sync Key` -> `Verify Peer`.
8. Bob: `Sync Key` -> `Verify Peer`.
9. Alice: `Send Msg` to Bob.
10. Bob: `Pull Msgs` and verify decrypted message.
11. Optional security test: Bob `Block User` Alice, then Alice send again and verify blocked error.

---

## 7. Readability and documentation statement

The code is organized into readable modules with clear responsibilities:
- `server.py`: API endpoints, storage, and server-side workflow
- `client.py`: client commands, encryption/session logic, friend/message flow
- `gui_client.py`: GUI actions and input/output error handling

The implementation uses descriptive naming and comments for non-trivial logic, especially security-related flow (authentication, key exchange, encryption, verification, and message handling).

---

## 8. Troubleshooting (Windows)

- If you see missing module errors, use `.venv` Python:
  - `& ".\.venv\Scripts\python.exe" ...`
- If server raises TLS cert error, ensure:
  - `$env:IM_ALLOW_INSECURE_HTTP="1"`
- If `python` is not recognized, reopen CMD after installing Python or reinstall with PATH option enabled.
- If you see `ModuleNotFoundError: No module named '_cffi_backend'`, rebuild `.venv`:

```powershell
cd Path\COMP3334-Computer-System-Security
Remove-Item -Recurse -Force ".venv"
python -m venv .venv
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
& ".\.venv\Scripts\python.exe" -m pip install --no-cache-dir -r requirements.txt
```

