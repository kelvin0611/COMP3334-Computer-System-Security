# Requirement Mapping (Project [Rev.1])

This file maps implementation pieces to the brief's requirement IDs.

- `R1` Registration: `POST /auth/register` with unique username and PBKDF2-SHA256 password hash.
- `R2` Password + OTP login: `POST /auth/login` validates password and TOTP.
- `R3` Session invalidation: short-lived JWT expiry plus revocation on `POST /auth/logout`.
- `R4` Per-device identity keypair: generated locally in `client.py`; server stores public key only.
- `R5` Fingerprint / verification UI: `client.py sync-key` + persistent trust state via `trust-status` and `verify-peer`.
- `R6` Key change detection policy: on key change, client marks peer unverified and blocks sending until re-verified.
- `R7` Secure session establishment: X25519 ECDH shared secret with HKDF.
- `R8` Encryption + auth + AD binding: AES-GCM with AD containing sender/receiver/convo/counter/TTL.
- `R9` Replay protection: per-peer monotonic counter checked in `POST /replay/check/{peer}`.
- `R10` TTL policy: TTL included in AD and server metadata.
- `R11` Client deletion behavior: local inbox cache purges expired messages on client operations.
- `R12` Server best-effort expiry deletion: `cleanup_expired_messages`.
- `R13-R14` Friend request workflow/lifecycle: `POST /friends/request`, `GET /friends/requests`, `POST /friends/respond`.
- `R15` Blocking/removing: `POST /friends/block/{username}`, `DELETE /friends/{username}`.
- `R16` Anti-spam: only friends can send messages (`/messages/send` checks friendship) and rate limiting on registration/login/friend requests.
- `R17` Minimum delivery states: sender gets `sent`; receiver pull marks `delivered`.
- `R18` Delivered semantics: recipient sends E2EE-protected ACK via `POST /messages/ack-e2ee`; sender receives/decrypts ACK in pull flow.
- `R19` Metadata disclosure: timestamps and delivery events remain visible to server by design.
- `R20` Offline queue: server stores queued ciphertext for receiver.
- `R21` Retention/cleanup: expiry and max-age cleanup.
- `R22` Duplicate/replay robustness: counter checks and idempotent handling.
- `R23` Conversation list: `GET /conversations`.
- `R24` Unread counters: unread derived from non-acknowledged received messages.
- `R25` Paging/incremental loading: implemented `limit`/`offset` query params on `/friends/requests`, `/messages/pull`, and `/conversations`.

## Remaining work before final submission

- Finalize deployment certificate strategy and enable TLS in your actual target environment.
- Validate OS keychain flow on clean target machines (Windows/macOS/Linux backend differences).
- Expand security testing section with at least 2 concrete attack simulations and evidence.

