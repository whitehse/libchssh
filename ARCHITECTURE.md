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
| `lab_mode=0` | **Production** (OpenSSL): `diffie-hellman-group14-sha256`, RSA host key (`rsa-sha2-256` signatures), `aes128-ctr`, `hmac-sha2-256`. Ephemeral RSA-2048 or PEM via `host_key_path`. |

### Production modules

| File | Role |
|------|------|
| `src/chssh_crypto.c` | OpenSSL: RSA, DH group14, SHA-256, AES-CTR, HMAC-SHA2-256, key derivation |
| `src/chssh.c` | SM, packets (plain + encrypted), KEXDH, auth, channels |

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

## Deliberate absences

- curve25519 / ed25519 (RSA preferred for field OLTs first).
- Port forwarding, shell, sftp, agent forwarding.
- Calix identity XML (host/edgehost).
- NETCONF XML framing (libnetconf).
- known_hosts pinning (client accepts any when `accept_any_hostkey`).
