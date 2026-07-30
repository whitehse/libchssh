# TODO — libchssh

## Done (v0.1)

- [x] Agent-ready scaffold + common ADRs
- [x] Public API: create/feed/get_output/next_event/flush_ident/channel_send
- [x] Identification hold/flush (Call Home host control)
- [x] Binary packet framing (lab cleartext)
- [x] Lab mode: service, password auth, session, subsystem netconf
- [x] Dialectic + hold_ident + smoke tests

## Done (v0.2 production crypto)

- [x] OpenSSL production KEX: `diffie-hellman-group14-sha256`
- [x] Host key: ephemeral RSA-2048 + PEM load (`host_key_path`)
- [x] Host key algorithms: `rsa-sha2-256` (sign) / `ssh-rsa` blob
- [x] Encryption: `aes128-ctr` + `hmac-sha2-256`
- [x] Production dialectic test (encrypted channel data)
- [x] PEM host key load test
- [x] Optional OpenSSH client interop harness (`chssh_openssh_server` + script; needs `sshpass`)

## Next

- [x] Multi-channel + named subsystems (ADR 015; CPE call-home)
- [x] Server-initiated session+shell (staff reverse; CPE design PR-2)
- [x] `pty-req` / `window-change` / `env` + want_reply discipline (OpenSSH interactive)
- [ ] Wire interop green on CI with `sshpass` + assert READY/hello
- [ ] OpenSSH interactive staff shell e2e (`sshpass` + staff face)
- [ ] `tcpip-forward` / `forwarded-tcpip` / `direct-tcpip` (reverse tunnels)
- [ ] curve25519-sha256 KEX (optional modern path)
- [ ] ed25519 host keys (keep RSA preferred for field OLTs)
- [ ] Host key pin / known_hosts for client role
- [x] edgehost `e7_callhome` integration (libchssh preferred path)
- [ ] libnetconf optional backend via libchssh
- [ ] Fuzz corpus for identification + encrypted packet parser
- [ ] mbedTLS crypto backend for OpenWrt CPE agent
