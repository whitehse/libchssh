# ADR 015: Multi-channel + named subsystems (CPE Call Home)

**Date**: 2026-07-28  
**Status**: Accepted  
**Deciders**: Edge Platform / CPE SSH Call Home

## Context

libchssh was specialized for a **single** session channel and subsystem
`netconf` (ADR 014, E7 Call Home). CPE sole-transport design requires:

- Multiple concurrent channels on one SSH connection
- Named subsystems: `edge-telemetry`, `edge-pg`, `edge-ai`, `edge-control`
- Later: server-initiated session+shell toward the CPE client (staff support)

Full product design: `~/edgehost/docs/designs/cpe-ssh-callhome.md`.

## Decision

1. Add a **fixed channel table** (default max 16) with per-channel windows and state.
2. Extend events with **`channel_id`** (local id) for OPEN / DATA / SUBSYSTEM / CLOSE.
3. Public APIs:
   - `chssh_channel_open_session` — open a session channel
   - `chssh_channel_request_subsystem(ctx, local_id, name)`
   - `chssh_channel_send_id` — send on a specific channel
   - Keep `chssh_channel_send` as send-on-primary-ready (E7/netconf compat)
4. Config:
   - `allowed_subsystems` — comma-separated allowlist (default: `netconf`)
   - `auto_open_netconf` — default **1**: client auto-opens netconf after auth
     (E7 path). Set **0** for app-driven multi-subsystem clients (CPE).
5. Server accepts subsystem names only if on the allowlist; success → channel READY.
6. `CHSSH_EVENT_READY` still fires when subsystem **`netconf`** becomes ready
   (E7 unchanged). Other subsystems emit `CHSSH_EVENT_SUBSYSTEM` only.
7. Server-initiated shell opens land in a follow-on PR (ADR amendment or 016).

## Consequences

- Larger context struct; still no sockets/callbacks.
- Dialectic tests cover multi-subsystem lab_mode.
- edgehost E7 path keeps `auto_open_netconf` default behavior.
- Not a general SSH product (no sftp/agent/X11 in this ADR).

## Alternatives considered

- **direct-tcpip only** — rejected for CPE product (named subsystems chosen).
- **Separate SSH connections per service** — defeats sole-transport goal.
- **New library** — rejected; extend plumbing with clear compat flags.
