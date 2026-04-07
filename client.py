import argparse
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone

import requests
try:
    import keyring  # type: ignore[reportMissingImports]
except ImportError:
    keyring = None
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def normalize_server_url(raw: str | None) -> str:
    """Accept plain http(s) URL or accidental Markdown / rich-text paste like [http://host](http://host/)."""
    default = "http://127.0.0.1:8000"
    if not raw:
        return default
    s = raw.strip()
    md = re.fullmatch(r"\[([^\]]*)\]\(([^)]+)\)", s)
    if md:
        s = md.group(2).strip()
    elif "](" in s:
        m = re.search(r"\]\((https?://[^)\s]+)\)", s)
        if m:
            s = m.group(1).strip()
    if s.startswith("<") and s.endswith(">"):
        s = s[1:-1].strip()
    m = re.match(r"^(https?://[^\s\])]+)", s)
    if m:
        s = m.group(1)
    s = s.rstrip("/")
    if not re.match(r"^https?://", s, re.I):
        return default
    return s


SERVER = normalize_server_url(os.environ.get("IM_SERVER"))
STATE_FILE = "client_state.json"
LOCAL_INBOX_FILE = "local_inbox.json"
KEYRING_SERVICE = "COMP3334_SECURE_IM"


def now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {
            "username": "",
            "token": "",
            "otp_secret": "",
            "identity_privkey": "",
            "peer_keys": {},
            "counters": {},
            "peer_verified": {},
            "trusted_fingerprints": {},
            "key_change_blocked": {},
            "identity_privkey_enc": "",
            "state_crypto": {},
            "key_storage": "plain",
        }
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        state = json.load(f)
    state.setdefault("peer_keys", {})
    state.setdefault("counters", {})
    state.setdefault("peer_verified", {})
    state.setdefault("trusted_fingerprints", {})
    state.setdefault("key_change_blocked", {})
    state.setdefault("identity_privkey_enc", "")
    state.setdefault("state_crypto", {})
    state.setdefault("key_storage", "plain")
    return state


def save_state(state: dict):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def get_state_passphrase() -> str:
    return os.environ.get("IM_STATE_PASSPHRASE", "")


def keyring_account(state: dict) -> str:
    username = state.get("username", "").strip()
    if not username:
        raise RuntimeError("Username is required for keyring operations")
    return f"{username}:identity_privkey"


def keyring_available() -> bool:
    return keyring is not None


def store_key_in_keyring(state: dict, priv_b64: str) -> bool:
    if not keyring_available():
        return False
    try:
        keyring.set_password(KEYRING_SERVICE, keyring_account(state), priv_b64)
        state["key_storage"] = "keyring"
        state["identity_privkey"] = ""
        state["identity_privkey_enc"] = ""
        state["state_crypto"] = {}
        return True
    except Exception:
        return False


def get_key_from_keyring(state: dict) -> str:
    if not keyring_available():
        raise RuntimeError("keyring dependency is not available")
    value = keyring.get_password(KEYRING_SERVICE, keyring_account(state))
    if not value:
        raise RuntimeError("No identity key found in OS keychain for this user")
    return value


def state_fernet_key(passphrase: str, salt_b64: str, iterations: int) -> bytes:
    salt = b64d(salt_b64)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def get_identity_privkey(state: dict) -> str:
    # Storage priority: OS keychain > plaintext state > encrypted local state.
    if state.get("key_storage") == "keyring":
        return get_key_from_keyring(state)
    if state.get("identity_privkey"):
        return state["identity_privkey"]
    enc = state.get("identity_privkey_enc", "")
    if not enc:
        raise RuntimeError("Identity private key not found in local state")
    passphrase = get_state_passphrase()
    if not passphrase:
        raise RuntimeError("Encrypted local key is configured. Set IM_STATE_PASSPHRASE to decrypt it.")
    sc = state.get("state_crypto", {})
    key = state_fernet_key(passphrase, sc["salt"], int(sc.get("iterations", 390000)))
    return Fernet(key).decrypt(enc.encode("utf-8")).decode("utf-8")


def encrypt_identity_key_in_state(state: dict, force: bool = False) -> bool:
    passphrase = get_state_passphrase()
    if not passphrase:
        return False
    plain = state.get("identity_privkey", "")
    if not plain and not force:
        return False
    sc = state.get("state_crypto", {})
    if not sc.get("salt"):
        sc = {"kdf": "pbkdf2-sha256", "iterations": 390000, "salt": b64(os.urandom(16))}
        state["state_crypto"] = sc
    key = state_fernet_key(passphrase, sc["salt"], int(sc["iterations"]))
    token = Fernet(key).encrypt(plain.encode("utf-8")).decode("utf-8")
    state["identity_privkey_enc"] = token
    state["identity_privkey"] = ""
    state["key_storage"] = "encrypted_state"
    return True


def migrate_identity_key_to_best_storage(state: dict) -> str:
    # Try strongest local protection first; keep plaintext only as last fallback.
    plain = state.get("identity_privkey", "")
    if not plain:
        return state.get("key_storage", "plain")
    if store_key_in_keyring(state, plain):
        return "keyring"
    if encrypt_identity_key_in_state(state):
        return "encrypted_state"
    return "plain"


def load_local_inbox() -> list:
    if not os.path.exists(LOCAL_INBOX_FILE):
        return []
    with open(LOCAL_INBOX_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_local_inbox(items: list):
    with open(LOCAL_INBOX_FILE, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)


def purge_local_expired_messages() -> int:
    now = now_ts()
    items = load_local_inbox()
    kept = [x for x in items if int(x.get("expires_at_ts", now + 1)) > now]
    removed = len(items) - len(kept)
    if removed:
        save_local_inbox(kept)
    return removed


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def generate_identity_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64(priv_bytes), b64(pub_bytes)


def fingerprint(pubkey_b64: str) -> str:
    fp = hashlib.sha256(b64d(pubkey_b64)).hexdigest()
    return ":".join([fp[i : i + 2] for i in range(0, len(fp), 2)])


def derive_key(my_priv_b64: str, peer_pub_b64: str) -> bytes:
    priv = x25519.X25519PrivateKey.from_private_bytes(b64d(my_priv_b64))
    peer = x25519.X25519PublicKey.from_public_bytes(b64d(peer_pub_b64))
    shared = priv.exchange(peer)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"COMP3334-E2EE")
    return hkdf.derive(shared)


def auth_headers(state: dict) -> dict:
    return {"Authorization": f"Bearer {state['token']}"}


def register(username: str, password: str):
    state = load_state()
    priv, pub = generate_identity_keypair()
    resp = requests.post(
        f"{SERVER}/auth/register",
        json={"username": username, "password": password, "identity_pubkey": pub},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    state["username"] = username
    state["otp_secret"] = data["otp_secret"]
    state["identity_privkey"] = priv
    mode = migrate_identity_key_to_best_storage(state)
    if mode == "keyring":
        print("Local identity key stored in OS keychain.")
    elif mode == "encrypted_state":
        print("Local identity key encrypted at rest.")
    else:
        print("WARNING: Local identity key is plaintext. Install keyring or set IM_STATE_PASSPHRASE.")
    save_state(state)
    print("Registered.")
    print("OTP secret (store in authenticator):", data["otp_secret"])
    print("OTP URI:", data["otp_uri"])
    print("Identity fingerprint:", fingerprint(pub))


def login(username: str, password: str, otp: str):
    state = load_state()
    resp = requests.post(f"{SERVER}/auth/login", json={"username": username, "password": password, "otp": otp}, timeout=10)
    resp.raise_for_status()
    state["username"] = username
    state["token"] = resp.json()["access_token"]
    if state.get("identity_privkey"):
        mode = migrate_identity_key_to_best_storage(state)
        if mode == "keyring":
            print("Migrated local identity key to OS keychain.")
        elif mode == "encrypted_state":
            print("Migrated local identity key to encrypted storage.")
    save_state(state)
    print("Logged in.")


def logout():
    state = load_state()
    try:
        resp = requests.post(f"{SERVER}/auth/logout", headers=auth_headers(state), timeout=10)
        if resp.ok:
            print(resp.json())
        else:
            print(f"Server logout: {resp.status_code} {resp.text}")
    finally:
        state["token"] = ""
        save_state(state)
        print("Local session cleared.")


def add_friend(target: str):
    state = load_state()
    resp = requests.post(f"{SERVER}/friends/request", json={"receiver": target}, headers=auth_headers(state), timeout=10)
    resp.raise_for_status()
    print(resp.json())


def block_user(target: str):
    state = load_state()
    resp = requests.post(f"{SERVER}/friends/block/{target}", headers=auth_headers(state), timeout=10)
    resp.raise_for_status()
    print(resp.json())


def remove_friend(target: str):
    state = load_state()
    resp = requests.delete(f"{SERVER}/friends/{target}", headers=auth_headers(state), timeout=10)
    resp.raise_for_status()
    print(resp.json())


def friend_requests(limit: int, offset: int):
    state = load_state()
    resp = requests.get(
        f"{SERVER}/friends/requests",
        headers=auth_headers(state),
        params={"limit": limit, "offset": offset},
        timeout=10,
    )
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2, default=str))


def respond_request(request_id: int, action: str):
    state = load_state()
    resp = requests.post(
        f"{SERVER}/friends/respond",
        json={"request_id": request_id, "action": action},
        headers=auth_headers(state),
        timeout=10,
    )
    resp.raise_for_status()
    print(resp.json())


def cancel_friend_request(request_id: int):
    state = load_state()
    resp = requests.post(
        f"{SERVER}/friends/cancel",
        json={"request_id": request_id},
        headers=auth_headers(state),
        timeout=10,
    )
    resp.raise_for_status()
    print(resp.json())

def sync_peer_key(peer: str, quiet: bool = False):
    state = load_state()
    resp = requests.get(f"{SERVER}/users/{peer}/identity", headers=auth_headers(state), timeout=10)
    resp.raise_for_status()
    pub = resp.json()["identity_pubkey"]
    old = state["peer_keys"].get(peer)
    new_fp = fingerprint(pub)
    state["peer_keys"][peer] = pub

    # Strict key-change policy: any identity key rotation forces re-verification.
    if old and old != pub:
        state["peer_verified"][peer] = False
        state["key_change_blocked"][peer] = True
        if not quiet:
            print("WARNING: Identity key changed for", peer)
            print("Old FP:", fingerprint(old))
            print("New FP:", new_fp)
            print("Strict policy: sending is blocked until you run: verify-peer --user", peer)
    else:
        # First-seen keys are also unverified by default.
        if peer not in state["peer_verified"]:
            state["peer_verified"][peer] = False
        if not quiet:
            print("Peer fingerprint:", new_fp)
            if not state["peer_verified"].get(peer, False):
                print("Peer is UNVERIFIED. Run: verify-peer --user", peer)
    save_state(state)


def verify_peer(peer: str):
    state = load_state()
    if peer not in state["peer_keys"]:
        sync_peer_key(peer)
        state = load_state()
    fp = fingerprint(state["peer_keys"][peer])
    state["peer_verified"][peer] = True
    state["trusted_fingerprints"][peer] = fp
    state["key_change_blocked"][peer] = False
    save_state(state)
    print(f"Verified {peer}. Trusted fingerprint: {fp}")


def trust_status(peer: str):
    state = load_state()
    if peer not in state["peer_keys"]:
        print(f"No key known for {peer}. Run sync-key first.")
        return
    fp = fingerprint(state["peer_keys"][peer])
    print(
        json.dumps(
            {
                "peer": peer,
                "fingerprint": fp,
                "verified": bool(state["peer_verified"].get(peer, False)),
                "blocked_due_to_key_change": bool(state["key_change_blocked"].get(peer, False)),
                "trusted_fingerprint": state["trusted_fingerprints"].get(peer),
            },
            indent=2,
        )
    )


def encrypt_local_key():
    state = load_state()
    if not state.get("identity_privkey"):
        print("No plaintext key to encrypt (already encrypted or not initialized).")
        return
    if encrypt_identity_key_in_state(state, force=True):
        save_state(state)
        print("Local identity key encrypted.")
    else:
        print("Set IM_STATE_PASSPHRASE first, then run encrypt-local-key.")


def migrate_local_key_to_keychain():
    state = load_state()
    if not keyring_available():
        print("keyring is not available. Install dependencies first.")
        return
    if state.get("key_storage") == "keyring":
        print("Already using OS keychain storage.")
        return
    try:
        priv = get_identity_privkey(state)
    except Exception as exc:
        print(f"Cannot read local key for migration: {exc}")
        return
    if store_key_in_keyring(state, priv):
        save_state(state)
        print("Migrated local identity key to OS keychain.")
    else:
        print("Failed to store key in OS keychain.")


def key_storage_status():
    state = load_state()
    status = {"mode": state.get("key_storage", "plain"), "keyring_available": keyring_available()}
    if status["mode"] == "keyring":
        try:
            _ = get_key_from_keyring(state)
            status["keyring_entry_present"] = True
        except Exception:
            status["keyring_entry_present"] = False
    print(json.dumps(status, indent=2))


def send_message(peer: str, plaintext: str, ttl: int):
    state = load_state()
    purge_local_expired_messages()
    if peer not in state["peer_keys"]:
        sync_peer_key(peer)
        state = load_state()
    if not state["peer_verified"].get(peer, False) or state["key_change_blocked"].get(peer, False):
        raise RuntimeError(
            f"Peer {peer} is not trusted due to verification policy. Run sync-key and verify-peer before sending."
        )
    my_priv = get_identity_privkey(state)
    key = derive_key(my_priv, state["peer_keys"][peer])
    aes = AESGCM(key)
    nonce = os.urandom(12)
    counter_key = f"{state['username']}->{peer}"
    counter = state["counters"].get(counter_key, 0) + 1
    state["counters"][counter_key] = counter
    convo_id = "|".join(sorted([state["username"], peer]))
    ad_obj = {
        "sender": state["username"],
        "receiver": peer,
        "convo_id": convo_id,
        "msg_counter": counter,
        "ttl_seconds": ttl,
        "sent_at": now_ts(),
    }
    ad = json.dumps(ad_obj, separators=(",", ":")).encode("utf-8")
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), ad)
    payload = {
        "receiver": peer,
        "convo_id": convo_id,
        "ciphertext": b64(ct),
        "nonce": b64(nonce),
        "ad": b64(ad),
        "msg_counter": counter,
        "ttl_seconds": ttl,
    }
    # Persist the message counter before the network request so retries/failures
    # do not accidentally reuse an already-seen counter value at the receiver.
    save_state(state)
    resp = requests.post(f"{SERVER}/messages/send", json=payload, headers=auth_headers(state), timeout=10)
    resp.raise_for_status()
    print(resp.json())


def send_e2ee_ack(state: dict, peer: str, message_id: int):
    my_priv = get_identity_privkey(state)
    key = derive_key(my_priv, state["peer_keys"][peer])
    aes = AESGCM(key)
    nonce = os.urandom(12)
    # ACK counter is separated from chat counter to avoid collisions.
    counter_key = f"{state['username']}->ack->{peer}"
    counter = state["counters"].get(counter_key, 0) + 1
    state["counters"][counter_key] = counter
    convo_id = "|".join(sorted([state["username"], peer]))
    ttl = 300
    ad_obj = {
        "type": "ack",
        "sender": state["username"],
        "receiver": peer,
        "convo_id": convo_id,
        "msg_counter": counter,
        "ttl_seconds": ttl,
        "sent_at": now_ts(),
        "orig_message_id": message_id,
    }
    ad = json.dumps(ad_obj, separators=(",", ":")).encode("utf-8")
    body = json.dumps({"type": "ack", "message_id": message_id}, separators=(",", ":")).encode("utf-8")
    ct = aes.encrypt(nonce, body, ad)
    payload = {
        "receiver": peer,
        "convo_id": convo_id,
        "ciphertext": b64(ct),
        "nonce": b64(nonce),
        "ad": b64(ad),
        "msg_counter": counter,
        "ttl_seconds": ttl,
    }
    save_state(state)
    resp = requests.post(f"{SERVER}/messages/ack-e2ee", json=payload, headers=auth_headers(state), timeout=10)
    resp.raise_for_status()


def pull(limit: int, offset: int):
    state = load_state()
    removed = purge_local_expired_messages()
    if removed:
        print(f"Purged {removed} expired local message(s).")
    resp = requests.get(
        f"{SERVER}/messages/pull",
        headers=auth_headers(state),
        params={"limit": limit, "offset": offset},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    for msg in data["messages"]:
        sender = msg["sender"]
        sync_peer_key(sender, quiet=True)
        state = load_state()
        if not state["peer_verified"].get(sender, False) or state["key_change_blocked"].get(sender, False):
            print(
                f"Skipped message {msg['id']} from {sender}: sender key is unverified/changed. "
                "Run verify-peer after out-of-band verification."
            )
            continue
        counter = msg["msg_counter"]
        # Receiver asks server replay-check endpoint before decryption.
        replay = requests.post(
            f"{SERVER}/replay/check/{sender}",
            params={"counter": counter},
            headers=auth_headers(state),
            timeout=10,
        )
        replay.raise_for_status()
        if not replay.json()["accept"]:
            print(f"Replay dropped from {sender}, counter={counter}")
            continue
        if sender not in state["peer_keys"]:
            sync_peer_key(sender)
            state = load_state()
        my_priv = get_identity_privkey(state)
        key = derive_key(my_priv, state["peer_keys"][sender])
        aes = AESGCM(key)
        ad = b64d(msg["ad"])
        nonce = b64d(msg["nonce"])
        ct = b64d(msg["ciphertext"])
        try:
            pt = aes.decrypt(nonce, ct, ad).decode("utf-8")
        except Exception:
            print(f"Failed to decrypt message {msg['id']} from {sender}")
            continue

        ad_obj = json.loads(ad.decode("utf-8"))
        kind = msg.get("kind", "chat")
        if kind == "ack":
            try:
                ack_obj = json.loads(pt)
            except json.JSONDecodeError:
                print(f"Invalid ACK payload from {sender}")
                continue
            print(f"[delivery] message {ack_obj.get('message_id')} acknowledged by {sender}")
            continue
        expires_at = msg["expires_at"]
        print(f"[{sender}] {pt} | ttl={ad_obj['ttl_seconds']} | expires={expires_at}")
        local = load_local_inbox()
        local.append(
            {
                "id": msg["id"],
                "sender": sender,
                "plaintext": pt,
                "expires_at": expires_at,
                "expires_at_ts": int(datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc).timestamp()),
            }
        )
        save_local_inbox(local)
        send_e2ee_ack(state, sender, msg["id"])
    save_state(state)


def list_conversations():
    state = load_state()
    resp = requests.get(f"{SERVER}/conversations", headers=auth_headers(state), timeout=10)
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2, default=str))


def list_conversations_paged(limit: int, offset: int):
    state = load_state()
    resp = requests.get(
        f"{SERVER}/conversations",
        headers=auth_headers(state),
        params={"limit": limit, "offset": offset},
        timeout=10,
    )
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(description="COMP3334 Secure IM client")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("register")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)

    p = sub.add_parser("login")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--otp", required=True)

    sub.add_parser("logout")

    p = sub.add_parser("add-friend")
    p.add_argument("--user", required=True)
    p = sub.add_parser("block-user")
    p.add_argument("--user", required=True)
    p = sub.add_parser("remove-friend")
    p.add_argument("--user", required=True)

    p = sub.add_parser("friend-requests")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("accept")
    p.add_argument("--id", type=int, required=True)
    p = sub.add_parser("decline")
    p.add_argument("--id", type=int, required=True)
    p = sub.add_parser("cancel-request")
    p.add_argument("--id", type=int, required=True)

    p = sub.add_parser("sync-key")
    p.add_argument("--user", required=True)
    p = sub.add_parser("verify-peer")
    p.add_argument("--user", required=True)
    p = sub.add_parser("trust-status")
    p.add_argument("--user", required=True)
    sub.add_parser("encrypt-local-key")
    sub.add_parser("migrate-local-key-keychain")
    sub.add_parser("key-storage-status")

    p = sub.add_parser("send")
    p.add_argument("--to", required=True)
    p.add_argument("--text", required=True)
    p.add_argument("--ttl", type=int, default=60)

    p = sub.add_parser("pull")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--offset", type=int, default=0)
    p = sub.add_parser("conversations")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--offset", type=int, default=0)

    args = parser.parse_args()

    if args.cmd == "register":
        register(args.username, args.password)
    elif args.cmd == "login":
        login(args.username, args.password, args.otp)
    elif args.cmd == "logout":
        logout()
    elif args.cmd == "add-friend":
        add_friend(args.user)
    elif args.cmd == "block-user":
        block_user(args.user)
    elif args.cmd == "remove-friend":
        remove_friend(args.user)
    elif args.cmd == "friend-requests":
        friend_requests(args.limit, args.offset)
    elif args.cmd == "accept":
        respond_request(args.id, "accept")
    elif args.cmd == "decline":
        respond_request(args.id, "decline")
    elif args.cmd == "cancel-request":
        cancel_friend_request(args.id)
    elif args.cmd == "sync-key":
        sync_peer_key(args.user)
    elif args.cmd == "verify-peer":
        verify_peer(args.user)
    elif args.cmd == "trust-status":
        trust_status(args.user)
    elif args.cmd == "encrypt-local-key":
        encrypt_local_key()
    elif args.cmd == "migrate-local-key-keychain":
        migrate_local_key_to_keychain()
    elif args.cmd == "key-storage-status":
        key_storage_status()
    elif args.cmd == "send":
        send_message(args.to, args.text, args.ttl)
    elif args.cmd == "pull":
        pull(args.limit, args.offset)
    elif args.cmd == "conversations":
        list_conversations_paged(args.limit, args.offset)


if __name__ == "__main__":
    main()

