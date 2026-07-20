# ADR 004: Dialectic Client+Server Implementation for Protocol Code

**Date**: 2026-06-27  
**Status**: Accepted  
**Deciders**: Project maintainers (via agent directive)

## Context
The CHSSH protocol is inherently two-sided (frontend/client and backend/server). Implementing only one side risks incomplete protocol coverage, asymmetric bugs, and tests that cannot exercise full request/response cycles without external dependencies (real sockets, event loops, or third-party clients/servers).

The existing scaffold uses a role parameter (`CHSSH_ROLE_CLIENT` / `CHSSH_ROLE_CALLHOME_SERVER`). Changes to the core state machine must remain pure (buffer-driven, no syscalls).

## Decision
Any implementation or extension that touches network protocol logic **must** implement symmetric support for both sides of the connection (client and server roles) inside the same state machine / library, at minimum to enable dialectic (paired) testing.

- The library exposes a single `chssh_ctx_t` that can be instantiated in either `CHSSH_ROLE_CLIENT` or `CHSSH_ROLE_CALLHOME_SERVER` mode.
- Client mode: emits StartupMessage, drives query initiation, processes server responses (including binary rows).
- Server mode: consumes startup/auth, emits RowDescription + DataRow (text or binary, including PostGIS), ReadyForQuery, etc.
- All testing of new message parsing, message format handling, or state logic uses paired in-memory client_ctx ↔ server_ctx exchanges (feed one's output buffer directly into the other's `chssh_feed_input`). No sockets, no blocking, no external processes.
- This principle is now a first-class architectural requirement alongside "no syscalls" and "pure state machine."

## Rationale
- Forces complete, symmetric protocol coverage.
- Enables hermetic, reproducible tests that exercise both code paths without network stack.
- Catches client/server asymmetry bugs early (e.g., startup parameter handling, binary vs text format negotiation, OID handling).
- Aligns with the "pure buffer" design: the test harness is just a simple loop shuttling byte arrays.
- Prevents future one-sided features that would be hard to test or verify.

## Consequences
- `chssh_create` (or `chssh_create_with_config`) accepts a role parameter; internal state machine branches on role.
- New tests in `tests/` must demonstrate client↔server roundtrips.
- Documentation (DOMAIN.md, ARCHITECTURE.md, AGENTS.md) updated to reference the dialectic requirement.
- Future protocol extensions (binary row decoding, PostGIS support, extended query protocol, COPY, notifications) must be exercised from both roles in tests.
- No change to the "all I/O lives in caller" rule — role only affects internal generation and parsing of messages.

## Verification
- `ctest` includes dialectic tests that pass with two contexts exchanging buffers.
- Build remains clean under strict warnings.
- No new syscalls or callbacks introduced.
- ADR referenced in future changes touching client/server paths.

This decision codifies the "dialectic development" mandate so that client and server code evolve together and are validated against each other.