# ADR 014: Call Home–specialized SSH transport (not a general SSH client)

**Date**: 2026-07-19  
**Status**: Accepted  
**Deciders**: Edge Platform / E7 Call Home work

## Context

edgehost must terminate NETCONF Call Home (RFC 8071) for Calix E7 shelves. General-purpose SSH libraries (libassh, OpenSSH) are broad: shells, port forwards, many algorithms, and limited host control over **when** the identification string is emitted on a socket that already carried a proprietary identity preamble.

Field debugging showed identity succeeds and any immediate wrong post-identity TX fails; the host needs explicit **hold/flush** of the SSH banner after Calix XML.

## Decision

Implement **libchssh**: a purpose-built, plumbing-only SSH transport for:

1. NMS as SSH **server** after TCP accept (Call Home)
2. Device as SSH **client** (dialectic / device-side)
3. Subsystem **`netconf` only**
4. Host-controlled identification (`hold_ident` / `chssh_flush_ident`)
5. OpenSSH-like default identification string for field gear
6. Sibling interface style (`create` / `feed_input` / `get_output` / `next_event`)

Calix identity XML and NETCONF XML remain outside this library (edgehost + libnetconf).

## Consequences

- Smaller attack/feature surface than a general SSH stack.
- Production crypto is incremental (OpenSSL); lab_mode unblocks dialectic and host integration of the API.
- libnetconf may later depend on libchssh instead of embedding libassh.
- Not a drop-in replacement for OpenSSH interactive use.

## Alternatives considered

- Keep only libassh inside libnetconf — insufficient Call Home host controls.
- Shell out to OpenSSH — violates pure plumbing / multi-session scale.
- Full from-scratch SSH in edgehost — wrong layer; violates core/host split.
