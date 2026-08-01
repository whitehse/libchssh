# ARCHITECTURE.md — libchssh

## Core principle

**Plumbing only** (ADR 006): parse/serialize SSH Call Home transport PDUs, emit structured events, never own sockets or policy. Same feed/get_output/next_event shape as libnetconf, librest, libcdp.

## Module boundaries

| Path | Role |
|------|------|
| `include/chssh.h` | Public API |
| `src/chssh.c` | State machine, identification, packets, lab handshake, channel |
| `src/chssh_internal.h` | Opaque context internals |

## Role model (RFC 8071)

| SSH role | TCP | Typical use |
|----------|-----|-------------|
| `CHSSH_ROLE_SERVER` | Acceptor | NMS after Call Home accept |
| `CHSSH_ROLE_CLIENT` | Initiator | E7/device Call Home, or outbound NMS |

NETCONF app role remains **client on NMS** / **server on device** in libnetconf after `CHSSH_STATE_READY`.

## Call Home sequence (host)

```
accept TCP
read Calix identity XML (host; not this library)
chssh_create(SERVER, hold_ident=1, lab_mode|production)
chssh_flush_ident()          ← first SSH bytes after identity
loop: feed_input / get_output / next_event
on READY: chssh_channel_send / CHANNEL_DATA ↔ libnetconf feed/get
```

## Lab vs production

| Mode | Purpose |
|------|---------|
| `lab_mode=1` | Dialectic + unit tests; KEXINIT advertises `chssh-lab-v1` + `none` cipher; NEWKEYS then cleartext binary packets. **Not** interoperable with OpenSSH/E7. |
| `lab_mode=0` | **Production**: `diffie-hellman-group14-sha256` (+ ECDH nistp256), RSA host key (`rsa-sha2-256`), `aes128-ctr`, `hmac-sha2-256`. Backend: **OpenSSL** (host) or **mbedTLS** (CPE/OpenWrt). All crypto is pure compute (non-blocking / no sockets). |

### Production modules

| File | Role |
|------|------|
| `src/chssh_crypto.c` | Backend select: OpenSSL / mbedTLS / none |
| `src/chssh_crypto_mbedtls.inc` | mbedTLS RSA, DH group14, ECDH P-256, AES-CTR, HMAC |
| `src/chssh.c` | SM, packets (plain + encrypted), KEX, auth, channels |

`chssh_crypto_backend()` returns `"openssl"` | `"mbedtls"` | `"none"`.

## State machine

```
IDENT → KEX → SERVICE → AUTH → CHANNEL → READY → CLOSED
                                              ↘ ERROR
```

## Field-oriented controls

- **Default ident** `SSH-2.0-OpenSSH_8.9` (field gear often rejects exotic banners).
- **`hold_ident`**: no TX until `chssh_flush_ident` — required when Calix identity shares the socket.
- **Subsystem fixed** to `netconf`.
- **Auth events** emitted; config passwords are default policy; `chssh_auth_decide` overrides.

## Invariants

- No `read`/`write`/`socket` in library.
- No callbacks; events are pulled.
- Embedded event payloads (copy-safe).
- Strict C11 + pedantic warnings as errors.

## Multi-channel (ADR 015)

Channel table (fixed max) supports concurrent session channels and named
subsystems beyond `netconf` (CPE: `edge-telemetry`, `edge-pg`, `edge-ai`,
`edge-control`). Default client still auto-opens `netconf` for E7
(`auto_open_netconf=1`).

## Interactive shell / PTY (staff reverse)

Channel requests for OpenSSH interactive clients:

| Request | Behavior |
|---------|----------|
| `pty-req` | Auto-accept + SUCCESS (want_reply); emit `CHSSH_EVENT_PTY` with term/cols/rows |
| `shell` | Auto-accept if `auto_accept_shell`; emit `CHSSH_EVENT_SHELL` |
| `exec` | Parse command; auto-accept if `auto_accept_shell`; emit `CHSSH_EVENT_EXEC` (SCP path — not collapsed to shell) |
| `subsystem` | Allowlist check (both roles); emit `CHSSH_EVENT_SUBSYSTEM` (`sftp`/`tun`/`tap`/edge-*) |
| `window-change` | Update dims; emit `CHSSH_EVENT_WINDOW_CHANGE`; SUCCESS if want_reply |
| `env` | SUCCESS if want_reply (values not stored) |
| other | FAILURE if want_reply (never silent-drop) |

PTY is plumbing only — host/agent owns real `posix_openpt` and `TIOCSWINSZ`.
SFTP/TUN/TAP are named subsystems; host/agent runs `sftp-server` or TUN/TAP fds.

## Deliberate absences

- curve25519 / ed25519 (RSA preferred for field OLTs first).
- ~~Port forwarding~~ — `tcpip-forward` / `cancel` / `forwarded-tcpip` / `direct-tcpip` (host owns sockets).
- ~~sftp subsystem~~ — allowlisted `sftp` + agent/host runs external `sftp-server`.
- agent forwarding / X11.
- Calix identity XML (host/edgehost).
- NETCONF XML framing (libnetconf).
- known_hosts pinning (client accepts any when `accept_any_hostkey`; pin API later — PR-3).
- Public key helpers (PR-1a): `chssh_pubkey_*` in `src/chssh_pubkey.c` — OpenSSH
  SHA256 fingerprints, RSA/ed25519 wire blob parse/encode, authorized_keys line
  codec.
- Userauth crypto (PR-1b/1c): `chssh_identity_*`, `chssh_userauth_build_signed_data`,
  `chssh_userauth_verify` — RSA (`rsa-sha2-256`) and ed25519 signatures over the
  RFC 4252 §7 message. OpenSSH unencrypted private keys via
  `src/chssh_openssh_key.c`. mbedTLS ed25519 uses portable orlp/ed25519
  (`third_party/ed25519/`). Wire SM (AUTH_PUBLICKEY events) is PR-2.
