# AGENTS.md — libchssh

**Project identity**: Pure C state-machine **Call Home SSH** transport library for NETCONF (RFC 8071 + RFC 4253 subset). System-call free, callback free. Specialized for NMS SSH **server** after TCP accept (and device SSH **client**), subsystem `netconf` only. Host owns sockets, Calix identity preamble, and auth policy.

**Key commands** (run from repo root):
- `cmake -B build -S . && cmake --build build` — configure and build static library + tests
- `ctest --test-dir build --output-on-failure` — run verification tests

**Documentation map**:
- AGENTS.md (this file) — start here
- ARCHITECTURE.md — module boundaries, lab vs production, invariants
- docs/README.md — documentation index
- docs/DOMAIN.md — Call Home SSH / NETCONF domain glossary
- docs/decisions/ — ADRs (common sibling decisions)

**Operating rules**:
- Never introduce system calls, callbacks, or hidden I/O in the core library.
- Progress is pull-driven: `chssh_feed_input` / `chssh_next_event` / `chssh_get_output`.
- Call Home host control: `hold_ident` + `chssh_flush_ident()` after Calix identity on the same TCP fd.
- NETCONF application roles live in **libnetconf** (`NETCONF_ROLE_CLIENT` after SSH READY). This library is SSH transport only.
- Strict warnings: `-Wall -Wextra -Wpedantic -Werror`.
- Prefer small patches; update ADRs when architecture changes.

**Definition of done**:
- Builds clean; `ctest` green.
- Docs accurate.
- No new syscalls/callbacks.
- Dialectic tests cover hold-ident → READY → channel data.

**Current status (v0.2)**:
- Identification exchange with **hold/flush** (field Call Home).
- **lab_mode=1**: dialectic cleartext path (not wire-interop).
- **lab_mode=0 (production)**: OpenSSL
  - KEX `diffie-hellman-group14-sha256`
  - Host key RSA-2048 (ephemeral or PEM), sign `rsa-sha2-256`
  - `aes128-ctr` + `hmac-sha2-256`
  - password userauth + session + subsystem `netconf`
- Tests: smoke, hold_ident, lab dialectic, production dialectic, PEM host key, optional OpenSSH client script.

**Dependencies**:
- **OpenSSL** (required for production KEX; linked when found).
- No libassh dependency.

**Interface direction**:
- `chssh_create(role, &cfg)` with `CHSSH_ROLE_SERVER` / `CHSSH_ROLE_CLIENT`
- `chssh_flush_ident` / `chssh_feed_input` / `chssh_get_output` / `chssh_next_event`
- `chssh_auth_decide` (server policy hook)
- `chssh_channel_send` after `CHSSH_STATE_READY`
