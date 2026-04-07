# Final Submission Checklist (COMP3334)

Use this checklist before submitting `TeamID.zip`.

## A) Code and Security Features

- [ ] `R1-R3` registration/login/logout works (password + OTP + token revocation).
- [ ] `R4-R6` identity key generated locally, fingerprint shown, verify/unverify and key-change block policy enforced.
- [ ] `R7-R9` E2EE messaging works with AD binding and replay protection.
- [ ] `R10-R12` TTL/self-destruct policy works on client and server cleanup.
- [ ] `R13-R16` friend request lifecycle, remove/block, anti-spam controls.
- [ ] `R17-R18` delivery semantics defined; E2EE ACK flow demonstrated.
- [ ] `R20-R22` offline ciphertext queue and duplicate/replay robustness validated.
- [ ] `R23-R25` conversation list, unread counters, pagination verified.

## B) Deployment and Hardening

- [ ] TLS is enabled for deployment environment (not only local HTTP).
- [ ] JWT secret replaced with strong secret from environment variable.
- [ ] Rate limits tuned and tested for abuse scenarios.
- [ ] Input validation and size limits tested with malformed payloads.
- [ ] Sensitive logging minimized (no keys/secrets/tokens in logs).

## C) Required Artifacts

- [ ] `code/` folder includes complete source code.
- [ ] Database import/init file included.
- [ ] Step-by-step deployment guide included for Windows 11 and/or Ubuntu from clean machine.
- [ ] Report completed using `REPORT_TEMPLATE.md` structure.
- [ ] Report includes at least 2 security test cases with evidence.
- [ ] 10-minute presentation video recorded.

## D) Packaging

- [ ] Folder structure exactly:
  - `TeamID/code/`
  - `TeamID/report.pdf` (or required extension)
  - `TeamID/video.mp4` (or required extension)
- [ ] Compressed as `TeamID.zip`.
- [ ] Final zip tested by unzipping and following the deployment guide on a clean environment.

## E) Demo Readiness

- [ ] Can demonstrate two-user flow end-to-end live.
- [ ] Can explain threat model, trust boundaries, and metadata leakage.
- [ ] Can explain crypto choices and parameter rationale.

