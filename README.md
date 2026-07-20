# libchssh

Pure C **Call Home SSH** transport library for NETCONF (RFC 8071).

System-call free plumbing: the caller owns TCP (and any Calix identity preamble). After SSH is `READY`, channel bytes are NETCONF framed by **libnetconf**.

## Features

- C11, no callbacks, no sockets in core
- SSH roles: **server** (NMS Call Home) / **client** (device)
- `hold_ident` + `chssh_flush_ident()` for same-socket identity → SSH
- OpenSSH-like default identification string
- Subsystem `netconf` only
- Lab dialectic mode for tests without production crypto
- **Production OpenSSL path**: DH group14-sha256, RSA host keys, AES-CTR, HMAC-SHA2-256
- Agent-ready docs (AGENTS.md, ARCHITECTURE.md, ADRs)

## Build

```bash
cmake -B build -S . && cmake --build build
ctest --test-dir build --output-on-failure
```

## Minimal Call Home (production)

```c
chssh_config_t cfg = {0};
cfg.lab_mode = 0;                 /* OpenSSL KEX + encrypt */
cfg.hold_ident = 1;               /* after Calix identity */
cfg.server_username = "sysadmin";
cfg.server_password = "sysadmin";
/* cfg.host_key_path = "/etc/edgehost/ssh_host_rsa_key"; optional PEM */
chssh_ctx_t *ssh = chssh_create(CHSSH_ROLE_SERVER, &cfg);
/* ... after identity on the accepted fd ... */
chssh_flush_ident(ssh);
/* feed_input(peer bytes); write get_output() to fd; next_event until READY */
chssh_channel_send(ssh, netconf_bytes, len);
```

## Minimal Call Home (lab dialectic)

```c
cfg.lab_mode = 1; /* cleartext after NEWKEYS — tests only */
```

## Documentation

See `AGENTS.md` and `docs/`.

## License

MIT. See `LICENSE`.
