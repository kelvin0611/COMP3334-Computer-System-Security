# COMP3334 Project Report Template

## 1. Team Information

- Team ID:
- Member 1 (Name, Student ID):
- Member 2 (Name, Student ID):
- Member 3 (Name, Student ID):

## 2. Abstract

Briefly summarize what was built, major security goals, and key outcomes.

## 3. Introduction

- What the system does (1:1 secure IM scope)
- Why E2EE is needed in HbC server model
- Main implemented features

## 4. Threat Model and Assumptions

### 4.1 Threat Model

- Honest-but-curious server capabilities
- External network attacker capabilities
- Malicious client/user capabilities

### 4.2 Assumptions and Out-of-Scope

- Device compromise assumptions
- Screenshot/copy limitations for self-destruct messages
- Multi-device synchronization not in scope

## 5. Architecture

### 5.1 Components

- Client responsibilities (E2EE, key handling, UI/CLI)
- Server responsibilities (auth, relay, queue, metadata)

### 5.2 Trust Boundaries

Describe which data crosses trust boundaries and why plaintext remains client-side only.

### 5.3 Data Flow

Add architecture/data-flow diagrams:
- Registration and login
- Friend request lifecycle
- Message send/store-forward/pull flow

## 6. Protocol Design

### 6.1 Session Establishment

- Identity key generation and publication
- Shared secret derivation process

### 6.2 Message Format and State

- Ciphertext payload fields
- Associated data fields and why they are bound
- Counter and replay handling
- TTL and expiry semantics

### 6.3 Delivery Status Semantics

- Define "Sent"
- Define "Delivered"
- Describe acknowledgement behavior

## 7. Cryptographic Choices and Rationale

Fill with exact library and version used from `requirements.txt`.

- Key agreement: X25519
- KDF: HKDF-SHA256
- Symmetric AEAD: AES-256-GCM
- Password hashing: PBKDF2-SHA256 (Passlib)
- OTP: TOTP (PyOTP)
- Token signing: JWT HS256

Justify:
- key sizes
- nonce generation
- random source
- safe API usage choices

## 8. Security Analysis

### 8.1 Why server cannot read plaintext

Explain key separation and ciphertext-only storage.

### 8.2 Integrity and authentication reasoning

Explain AEAD + AD field binding.

### 8.3 Metadata exposure and trade-offs

- login timing
- delivery timing
- contact graph
- message size/timestamp leakage

### 8.4 Limitations

- TLS setup status
- local key storage limitations
- key verification UX limitations

## 9. Testing and Evaluation

### 9.1 Functional Demonstrations

- Register/login with OTP
- Friend request accept/decline
- Offline message queue + pull
- TTL expiry behavior
- Conversation list and unread count

### 9.2 Security Test Case 1: Replay Attack

- **Goal:** Verify replayed ciphertext is not accepted.
- **Steps:**
  1. Send a valid message from A to B.
  2. Re-submit same ciphertext/counter.
  3. Pull on B.
- **Expected Result:** replay is dropped; no duplicate plaintext shown.
- **Evidence:** logs/screenshots/CLI output.

### 9.3 Security Test Case 2: Tampering with Associated Data

- **Goal:** Verify AD tampering causes decryption/authentication failure.
- **Steps:**
  1. Capture message payload in transit/storage.
  2. Modify `ad` (e.g., TTL or sender field) without re-encryption.
  3. Pull on receiver.
- **Expected Result:** decryption/authentication fails and message is rejected.
- **Evidence:** logs/screenshots/CLI output.

### 9.4 Additional Security Tests (Optional)

- brute-force login throttling
- key change warning behavior
- block list enforcement

## 10. Future Work

- TLS deployment with certificate management
- secure keychain/encrypted local key storage
- verified contact trust state and strict key-change policy
- stronger E2EE acknowledgement semantics

## 11. References

List standards, papers, docs, and libraries used.

Examples:
- RFC 6238 (TOTP)
- NIST docs for AEAD/KDF/password hashing guidance
- library documentation links

