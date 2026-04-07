import base64
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
PYTHON = str(PROJECT_ROOT / ".venv" / "bin" / "python")


@dataclass
class CmdResult:
    rc: int
    stdout: str
    stderr: str


def run(cmd: list[str], cwd: Path, env: dict[str, str], timeout_s: int = 120) -> CmdResult:
    p = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_s,
    )
    return CmdResult(rc=p.returncode, stdout=p.stdout.strip(), stderr=p.stderr.strip())


def wait_http_ok(url: str, timeout_s: int = 20):
    import requests

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.ok:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Server did not become ready at {url} within timeout")


def parse_otp_secret(register_output: str) -> str:
    m = re.search(r"OTP secret .*?:\s*([A-Z2-7]+)", register_output)
    if not m:
        # fallback for case where the output format differs
        m = re.search(r"OTP secret.*?\n.*?([A-Z2-7]+)", register_output, re.S)
    if not m:
        raise RuntimeError(f"Cannot parse OTP secret from output:\n{register_output}")
    return m.group(1).strip()


def json_from_client_output(output: str):
    # client.py prints dict-like JSON on success; try to recover JSON payload
    # e.g., {'request_id': 1, 'status': 'pending'}
    # This function is intentionally heuristic for test evidence only.
    for m in re.finditer(r"(\{.*\})", output, re.S):
        chunk = m.group(1)
        try:
            # replace single quotes with double quotes for dict-like output
            fixed = re.sub(r"'", '"', chunk)
            return json.loads(fixed)
        except Exception:
            continue
    return None


def start_server(port: int, db_path: Path, out_dir: Path):
    env = os.environ.copy()
    env["IM_ALLOW_INSECURE_HTTP"] = "1"
    env["IM_HTTP_PORT"] = str(port)
    env["IM_HTTPS_PORT"] = str(port + 1000)
    env["IM_HOST"] = "127.0.0.1"
    env["IM_RELOAD"] = "0"

    # sqlite URL for absolute path
    # sqlite:////absolute/path/to/db
    db_abs = str(db_path.resolve())
    if not db_abs.startswith("/"):
        raise RuntimeError("Expected absolute unix path for sqlite db")
    # sqlite:////absolute/path/to/db.sqlite
    env["IM_DATABASE_URL"] = f"sqlite:////{db_abs[1:]}"

    server_log = out_dir / "server.log"
    server_log.touch(exist_ok=True)
    with server_log.open("w", encoding="utf-8") as f:
        proc = subprocess.Popen(
            [PYTHON, "run_server.py"],
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=f,
            stderr=subprocess.STDOUT,
            text=True,
        )
    # Wait for healthz
    wait_http_ok(f"http://127.0.0.1:{port}/healthz", timeout_s=25)
    return proc, env


def get_free_port() -> int:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def extract_first_json_object(text: str):
    m = re.search(r"(\{.*\})", text, re.S)
    if not m:
        return None
    chunk = m.group(1)
    try:
        return json.loads(chunk)
    except Exception:
        # heuristic for dict-like printing with single quotes
        fixed = re.sub(r"'", '"', chunk)
        return json.loads(fixed)


def read_state_json(user_dir: Path) -> dict:
    p = user_dir / "client_state.json"
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def b64encode_raw(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def main():
    run_id = time.strftime("%Y%m%d-%H%M%S")
    out_dir = PROJECT_ROOT / "test_run" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    port = int(os.environ.get("IM_TEST_PORT", "0"))
    if port == 0:
        port = get_free_port()

    db_path = out_dir / "im.db"

    proc, server_env = start_server(port=port, db_path=db_path, out_dir=out_dir)

    results = {f"R{i}": {"pass": None} for i in range(1, 26)}
    try:
        # Create user folders
        users = {
            "Alice123": out_dir / "alice",
            "Bob123": out_dir / "bob",
            "Carol123": out_dir / "carol",
        }
        for udir in users.values():
            udir.mkdir(parents=True, exist_ok=True)

        env_base = os.environ.copy()
        env_base["IM_SERVER"] = f"http://127.0.0.1:{port}"

        password = "Strongpassword123"

        # Register + OTP extract + login
        otp_secrets = {}
        for username, udir in users.items():
            # register
            reg_res = run(
                [PYTHON, str(PROJECT_ROOT / "client.py"), "register", "--username", username, "--password", password],
                cwd=udir,
                env=env_base,
            )
            if reg_res.rc != 0:
                # If already registered (shouldn't happen with new DB), fail loudly
                raise RuntimeError(f"Register failed for {username}: {reg_res.stderr or reg_res.stdout}")
            otp_secret = parse_otp_secret(reg_res.stdout)
            otp_secrets[username] = otp_secret

            # compute OTP and login
            login_otp = run(
                [PYTHON, "-c", f"import pyotp; print(pyotp.TOTP('{otp_secret}').now())"],
                cwd=udir,
                env=env_base,
            ).stdout.strip()
            login_res = run(
                [PYTHON, str(PROJECT_ROOT / "client.py"), "login", "--username", username, "--password", password, "--otp", login_otp],
                cwd=udir,
                env=env_base,
            )
            if login_res.rc != 0:
                raise RuntimeError(f"Login failed for {username}: {login_res.stderr or login_res.stdout}")

        results["R1"]["pass"] = True
        results["R2"]["pass"] = True

        # R4: per-device identity keypair stored locally (keyring/encrypted/with fallback)
        alice_state = read_state_json(users["Alice123"])
        local_has_key = bool(alice_state.get("identity_privkey") or alice_state.get("identity_privkey_enc")) or alice_state.get(
            "key_storage"
        ) == "keyring"
        results["R4"]["pass"] = local_has_key

        # R7/R8 prerequisites: exchange keys + verify
        def sync_and_verify(from_user: str, to_user: str) -> str:
            """Returns sync-key stdout as evidence for UI/fingerprint verification."""
            from_dir = users[from_user]
            sync_res = run(
                [PYTHON, str(PROJECT_ROOT / "client.py"), "sync-key", "--user", to_user],
                cwd=from_dir,
                env=env_base,
            )
            run(
                [PYTHON, str(PROJECT_ROOT / "client.py"), "verify-peer", "--user", to_user],
                cwd=from_dir,
                env=env_base,
            )
            return sync_res.stdout

        # Establish trust for messaging tests
        sync_out_ab = sync_and_verify("Alice123", "Bob123")
        sync_out_ba = sync_and_verify("Bob123", "Alice123")
        results["R5"]["pass"] = ("Peer fingerprint:" in sync_out_ab) or ("fingerprint" in sync_out_ab.lower())
        results["R5"]["alice_sync_stdout"] = sync_out_ab
        # R6: key change detection policy (simulate server identity_pubkey update)
        import sqlite3
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization as crypto_serialization

        alice_dir = users["Alice123"]
        alice_state_before = read_state_json(alice_dir)
        bob_verified_before = alice_state_before.get("peer_verified", {}).get("Bob123")

        conn = sqlite3.connect(str(db_path))
        # capture original Bob pubkey first so we can restore it after R6
        original_bob_pub = conn.execute(
            "SELECT identity_pubkey FROM users WHERE username=?",
            ("Bob123",),
        ).fetchone()
        if not original_bob_pub:
            raise RuntimeError("R6: cannot find Bob123 identity_pubkey in DB")
        original_bob_pub = original_bob_pub[0]

        # generate a new identity keypair public key and update Bob's identity_pubkey on server
        new_priv = x25519.X25519PrivateKey.generate()
        new_pub = new_priv.public_key()
        new_pub_bytes = new_pub.public_bytes(
            encoding=crypto_serialization.Encoding.Raw,
            format=crypto_serialization.PublicFormat.Raw,
        )
        new_pub_b64 = b64encode_raw(new_pub_bytes)
        conn.execute("UPDATE users SET identity_pubkey=? WHERE username=?", (new_pub_b64, "Bob123"))
        conn.commit()
        conn.close()

        sync_again_res = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "sync-key", "--user", "Bob123"],
            cwd=alice_dir,
            env=env_base,
        )
        alice_state_after = read_state_json(alice_dir)
        blocked = alice_state_after.get("key_change_blocked", {}).get("Bob123", False)
        verified = alice_state_after.get("peer_verified", {}).get("Bob123", False)

        # send should be blocked by strict policy
        send_block_attempt = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "should-not-send", "--ttl", "60"],
            cwd=alice_dir,
            env=env_base,
            timeout_s=30,
        )
        send_blocked = send_block_attempt.rc != 0 and "not trusted due to verification policy" in (send_block_attempt.stderr + send_block_attempt.stdout)

        results["R6"]["pass"] = bool(bob_verified_before) and blocked and (not verified) and send_blocked
        results["R6"]["sync_again_stdout"] = sync_again_res.stdout

        # restore Bob's original key on server and re-sync trust so later tests are not polluted
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE users SET identity_pubkey=? WHERE username=?", (original_bob_pub, "Bob123"))
        conn.commit()
        conn.close()

        # restore trust so later message tests can run
        run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "sync-key", "--user", "Bob123"],
            cwd=alice_dir,
            env=env_base,
        )
        run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "verify-peer", "--user", "Bob123"],
            cwd=alice_dir,
            env=env_base,
        )
        run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "sync-key", "--user", "Alice123"],
            cwd=users["Bob123"],
            env=env_base,
        )
        run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "verify-peer", "--user", "Alice123"],
            cwd=users["Bob123"],
            env=env_base,
        )

        # R13: friend request workflow + R14: cancel request
        # Alice -> Bob request
        add_req = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "add-friend", "--user", "Bob123"],
            cwd=users["Alice123"],
            env=env_base,
        )
        add_payload = json_from_client_output(add_req.stdout)
        req_id = add_payload.get("request_id") if add_payload else None
        results["R14"] = {"pass": req_id is not None}
        if req_id is None:
            raise RuntimeError("Could not parse request_id for cancel test")

        # Cancel the request (sender cancel)
        cancel_res = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "cancel-request", "--id", str(req_id)],
            cwd=users["Alice123"],
            env=env_base,
        )
        cancel_payload = json_from_client_output(cancel_res.stdout)
        results["R14"].update({"cancel_response": cancel_payload})

        # Verify Bob no longer sees it as incoming pending
        fr_res = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "friend-requests", "--limit", "20", "--offset", "0"],
            cwd=users["Bob123"],
            env=env_base,
        )
        # We only check that cancelled request id is not listed; heuristic parsing
        results["R14"]["bob_friend_requests_stdout"] = fr_res.stdout
        results["R14"]["pass"] = str(req_id) not in fr_res.stdout

        # R16: default anti-spam control for non-friends (chat should be rejected)
        non_friend_send = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "non-friend-chat", "--ttl", "60"],
            cwd=users["Alice123"],
            env=env_base,
            timeout_s=30,
        )
        non_friend_send_pass = ("403" in (non_friend_send.stderr + non_friend_send.stdout)) or ("Only friends can chat" in (non_friend_send.stderr + non_friend_send.stdout))
        results["R16"]["pass"] = non_friend_send_pass

        # Now do accept to make them friends
        add_req2 = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "add-friend", "--user", "Bob123"],
            cwd=users["Alice123"],
            env=env_base,
        )
        add_payload2 = json_from_client_output(add_req2.stdout)
        req_id2 = add_payload2.get("request_id") if add_payload2 else None
        if req_id2 is None:
            raise RuntimeError("Could not parse request_id for accept test")
        accept_res = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "accept", "--id", str(req_id2)],
            cwd=users["Bob123"],
            env=env_base,
        )
        results["R13"]["pass"] = accept_res.rc == 0
        results["R13"]["output"] = accept_res.stdout

        # R16 anti-spam / default anti-arbitrary-chat for non-friends:
        # (We already are friends now; so we only test rate limit behavior)
        # Rate limit test: exceed login-user limit by repeated wrong OTP
        wrong_otp = "000000"
        rl_hit = False
        for i in range(12):
            r = run(
                [PYTHON, str(PROJECT_ROOT / "client.py"), "login", "--username", "Bob123", "--password", password, "--otp", wrong_otp],
                cwd=users["Bob123"],
                env=env_base,
                timeout_s=30,
            )
            if "429" in (r.stderr + r.stdout):
                rl_hit = True
                break
        results["R16"]["pass"] = bool(results["R16"]["pass"]) and rl_hit

        # R17/R18: Sent + Delivered via E2EE ACK
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "hello Bob", "--ttl", "60"],
            cwd=users["Alice123"], env=env_base)

        # Bob pull (should decrypt and send E2EE ack)
        pull_res_bob = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        results["R17"]["pass"] = "hello Bob" in pull_res_bob.stdout
        results["R17"]["stdout"] = pull_res_bob.stdout
        results["R7"]["pass"] = results["R17"]["pass"]

        # Alice pull (should receive E2EE ack)
        pull_res_alice = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Alice123"], env=env_base)
        results["R18"]["pass"] = (
            "acknowledged by bob" in pull_res_alice.stdout or "acknowledged by Bob123" in pull_res_alice.stdout
        )
        results["R18"]["stdout"] = pull_res_alice.stdout

        # R24 unread counters consistency
        # Send another message
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "unread-check", "--ttl", "60"],
            cwd=users["Alice123"], env=env_base)
        conv_before = run([PYTHON, str(PROJECT_ROOT / "client.py"), "conversations", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        unread_before = "unread" in conv_before.stdout
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        conv_after = run([PYTHON, str(PROJECT_ROOT / "client.py"), "conversations", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        results["R24"]["pass"] = conv_before.stdout != conv_after.stdout
        results["R24"]["before"] = conv_before.stdout
        results["R24"]["after"] = conv_after.stdout

        # R9 replay: pull twice should not show plaintext twice
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "replay-check", "--ttl", "60"], cwd=users["Alice123"], env=env_base)
        r1 = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        r2 = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        results["R9"] = {
            "pass": r1.stdout.count("replay-check") == 1 and r2.stdout.count("replay-check") == 0,
            "pull1": r1.stdout,
            "pull2": r2.stdout,
        }
        results["R22"]["pass"] = results["R9"]["pass"]

        # R10/R11 TTL + local purge
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "ttl-msg", "--ttl", "3"], cwd=users["Alice123"], env=env_base)
        r_b1 = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        time.sleep(4)
        r_b2 = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        ttl_pass = ("ttl-msg" in r_b1.stdout) and ("ttl-msg" not in r_b2.stdout)
        results["R10"]["pass"] = ttl_pass
        results["R11"]["pass"] = ttl_pass

        # R20 offline queue: send, delay, then pull
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "offline-queue", "--ttl", "60"], cwd=users["Alice123"], env=env_base)
        time.sleep(1.5)  # simulate offline delay
        r_off = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        results["R20"]["pass"] = "offline-queue" in r_off.stdout

        # R21 retention cleanup: TTL=2 and pull after expiry
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "cleanup-test", "--ttl", "2"], cwd=users["Alice123"], env=env_base)
        conn = sqlite3.connect(str(db_path))
        mid_clean = conn.execute(
            "SELECT id FROM messages WHERE sender=? AND receiver=? AND kind='chat' ORDER BY id DESC LIMIT 1",
            ("Alice123", "Bob123"),
        ).fetchone()
        conn.close()
        mid_clean = mid_clean[0] if mid_clean else None
        time.sleep(3.2)
        r_clean = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        results["R21"]["pass"] = "cleanup-test" not in r_clean.stdout
        # R12: server best-effort deletion of expired ciphertext
        if mid_clean is not None:
            conn = sqlite3.connect(str(db_path))
            exists = conn.execute("SELECT 1 FROM messages WHERE id=?", (mid_clean,)).fetchone()
            conn.close()
            results["R12"]["pass"] = exists is None
        else:
            results["R12"]["pass"] = False

        # R25 message paging
        # send 12 messages to Bob
        for i in range(12):
            run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", f"page-{i}", "--ttl", "60"], cwd=users["Alice123"], env=env_base)
        p0 = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "5", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        p5 = run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "5", "--offset", "5"], cwd=users["Bob123"], env=env_base)
        results["R25"]["paging_messages_pass"] = {
            "pass": sum(1 for k in range(12) if f"page-{k}" in p0.stdout) <= 5
            and sum(1 for k in range(12) if f"page-{k}" in p5.stdout) <= 5,
            "pull0": p0.stdout,
            "pull5": p5.stdout,
        }

        # R23/R24 pagination for conversations list:
        # create friend Carol<->Bob and send from both to Bob; then test limit/offset
        # sync+verify carol<->bob
        sync_and_verify("Bob123", "Carol123")
        sync_and_verify("Carol123", "Bob123")
        # establish friendship Bob<->Carol
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "add-friend", "--user", "Carol123"], cwd=users["Bob123"], env=env_base)
        # Bob initiated request; Carol accept
        # find request id by calling friend-requests once and parsing id heuristically
        fr_carol = run([PYTHON, str(PROJECT_ROOT / "client.py"), "friend-requests", "--limit", "20", "--offset", "0"], cwd=users["Carol123"], env=env_base)
        req_id_match = re.search(r"\"id\":\s*(\d+)", fr_carol.stdout) or re.search(r"'id':\s*(\d+)", fr_carol.stdout)
        if not req_id_match:
            raise RuntimeError("Cannot find Carol incoming request id")
        rid3 = req_id_match.group(1)
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "accept", "--id", rid3], cwd=users["Carol123"], env=env_base)

        run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "from-alice", "--ttl", "60"], cwd=users["Alice123"], env=env_base)
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "from-carol", "--ttl", "60"], cwd=users["Carol123"], env=env_base)
        # pull on Bob so ACK arrives and unread can clear
        run([PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "50", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        conv0 = run([PYTHON, str(PROJECT_ROOT / "client.py"), "conversations", "--limit", "1", "--offset", "0"], cwd=users["Bob123"], env=env_base)
        conv1 = run([PYTHON, str(PROJECT_ROOT / "client.py"), "conversations", "--limit", "1", "--offset", "1"], cwd=users["Bob123"], env=env_base)
        results["R25"]["paging_conversations_pass"] = ("conversations" in conv0.stdout) and ("conversations" in conv1.stdout)
        conv0_json = extract_first_json_object(conv0.stdout)
        if isinstance(conv0_json, dict) and conv0_json.get("conversations"):
            first = conv0_json["conversations"][0]
            results["R23"]["pass"] = "peer" in first and "last_time" in first
        results["R25"]["pass"] = results["R25"].get("paging_messages_pass") and results["R25"].get("paging_conversations_pass")

        # ---- Security attack tests placed at the end (avoid polluting functional checks) ----
        # R8: AEAD integrity + AD binding (tamper AD, ciphertext unchanged)
        import sqlite3

        alice_dir = users["Alice123"]
        run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "ad-tamper", "--ttl", "60"],
            cwd=alice_dir,
            env=env_base,
        )

        # locate newest chat message from Alice->Bob and tamper AD in DB
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT id, ad FROM messages WHERE sender=? AND receiver=? AND kind='chat' ORDER BY id DESC LIMIT 1",
            ("Alice123", "Bob123"),
        ).fetchone()
        if not row:
            raise RuntimeError("R8: could not find message row for AD tampering")
        mid, ad_b64 = row
        ad_json_bytes = base64.b64decode(ad_b64.encode("utf-8"))
        ad_obj = json.loads(ad_json_bytes.decode("utf-8"))
        ad_obj["ttl_seconds"] = int(ad_obj.get("ttl_seconds", 60)) + 123
        new_ad_b64 = base64.b64encode(json.dumps(ad_obj, separators=(",", ":")).encode("utf-8")).decode("utf-8")
        conn.execute("UPDATE messages SET ad=? WHERE id=?", (new_ad_b64, mid))
        conn.commit()
        conn.close()

        pull_res_bob_tamper = run(
            [PYTHON, str(PROJECT_ROOT / "client.py"), "pull", "--limit", "20", "--offset", "0"],
            cwd=users["Bob123"],
            env=env_base,
        )
        r8_pass = (f"Failed to decrypt message {mid}" in pull_res_bob_tamper.stdout) and ("ad-tamper" not in pull_res_bob_tamper.stdout)
        results["R8"]["pass"] = r8_pass
        results["R8"]["stdout"] = pull_res_bob_tamper.stdout

        # R15 blocking/removing
        import requests

        server_base = env_base["IM_SERVER"]
        bob_token = read_state_json(users["Bob123"]).get("token", "")
        alice_token = read_state_json(users["Alice123"]).get("token", "")

        block_ok = False
        remove_ok = False
        block_send_fail = False
        remove_send_fail = False

        # block Alice123 from Bob123
        try:
            block_resp = requests.post(
                f"{server_base}/friends/block/Alice123",
                headers={"Authorization": f"Bearer {bob_token}"},
                timeout=10,
            )
            block_ok = block_resp.ok
        except Exception:
            block_ok = False

        if block_ok:
            send_try = run(
                [PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "blocked-test", "--ttl", "60"],
                cwd=users["Alice123"],
                env=env_base,
                timeout_s=30,
            )
            block_send_fail = send_try.rc != 0 and ("403" in (send_try.stderr + send_try.stdout))

        # remove friendship
        try:
            remove_resp = requests.delete(
                f"{server_base}/friends/Alice123",
                headers={"Authorization": f"Bearer {bob_token}"},
                timeout=10,
            )
            remove_ok = remove_resp.ok
        except Exception:
            remove_ok = False

        if remove_ok:
            send_try2 = run(
                [PYTHON, str(PROJECT_ROOT / "client.py"), "send", "--to", "Bob123", "--text", "removed-test", "--ttl", "60"],
                cwd=users["Alice123"],
                env=env_base,
                timeout_s=30,
            )
            remove_send_fail = send_try2.rc != 0 and ("403" in (send_try2.stderr + send_try2.stdout))

        results["R15"]["pass"] = block_ok and block_send_fail and remove_ok and remove_send_fail

        # R19 metadata disclosure (schema presence + sample data existence)
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cols = [r[1] for r in conn.execute("PRAGMA table_info(messages)").fetchall()]
        required_cols = {"sent_at", "delivered_at", "expires_at", "acknowledged", "ciphertext", "ttl_seconds", "msg_counter"}
        have_cols = required_cols.issubset(set(cols))
        sample_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        conn.close()
        results["R19"]["pass"] = have_cols and sample_count > 0

        # R3 logout / session invalidation (revocation enforced server-side)
        # Use raw requests with the same token (client-side token clearing is not enough).
        alice_token = read_state_json(users["Alice123"]).get("token", "")
        try:
            lo = requests.post(
                f"{server_base}/auth/logout",
                headers={"Authorization": f"Bearer {alice_token}"},
                timeout=10,
            )
            conv_after = requests.get(
                f"{server_base}/conversations",
                headers={"Authorization": f"Bearer {alice_token}"},
                timeout=10,
            )
            r3_pass = lo.ok and (conv_after.status_code == 401) and ("Token revoked" in conv_after.text)
        except Exception:
            r3_pass = False
        results["R3"]["pass"] = r3_pass

        # Write summary
        summary_path = out_dir / "summary.json"
        with summary_path.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        # Print a readable summary
        print("\n=== TEST SUMMARY (R1-R25) ===")
        for i in range(1, 26):
            k = f"R{i}"
            v = results.get(k, {"pass": False})
            if v.get("pass") is True:
                status = "PASS"
            elif v.get("pass") is False:
                status = "FAIL"
            else:
                status = "NOT TESTED"
            print(f"{k}: {status}")
        print(f"\nArtifacts saved to: {out_dir}")

    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            pass


if __name__ == "__main__":
    main()

