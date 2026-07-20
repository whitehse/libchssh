# DOMAIN.md — libchssh

## Call Home SSH (RFC 8071)

Network devices (e.g. Calix E7) initiate TCP to the NMS. After the TCP connection is up, **SSH roles reverse relative to TCP**:

- **Device** = SSH client (and NETCONF server)
- **NMS** = SSH server (and NETCONF client)

This library implements the SSH transport slice only.

## Calix identity preamble

Some Calix shelves send a cleartext XML identity block **before** SSH on the same socket:

```xml
<version>1</version><identity><mac>…</mac>…</identity>
```

Identity is **not** part of SSH. Host (edgehost) parses it, then calls `chssh_flush_ident()` so the first application bytes after identity are a valid `SSH-2.0-…\r\n` banner.

## Subsystem netconf

RFC 6242: NETCONF over SSH uses channel type `session` and subsystem name `netconf`. This library does not open shells or other subsystems.

## Lab mode

`lab_mode` completes a Call Home handshake between two `chssh` peers without production cryptography. Use for dialectic tests and host integration of the plumbing API. Field E7 / OpenSSH require production KEX (planned).

## Glossary

| Term | Meaning |
|------|---------|
| Identification | `SSH-2.0-…\r\n` banner line |
| KEX | Key exchange (SSH_MSG_KEXINIT … NEWKEYS) |
| READY | Subsystem open; channel data = NETCONF framed bytes |
| hold_ident | Defer local banner until host finishes pre-SSH work |
