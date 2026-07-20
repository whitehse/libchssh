# ADR 002: Event-Loop Compatibility Requirement

**Date**: 2026-06-27  
**Status**: Accepted  
**Deciders**: Project maintainers (Hermes agent + human review)

## Context
The library is designed to be used exclusively from calling code that owns the event loop and all system calls. Four canonical event-loop / readiness mechanisms are expected to be used as reference examples by consumers:

- `liburing` (io_uring)
- `libev`
- `libuv`
- `epoll` (raw Linux epoll) or equivalent completion-based mechanisms

Any future change to the core state machine (`src/chssh.c`, `include/chssh.h`) must remain compatible with how these libraries and low-level approaches consume and drive the API.

## Decision
All changes to the core library **must** be compatible with the usage patterns demonstrated by the four reference event-loop styles.

The library shall remain:
- System-call free
- Callback free
- Driven exclusively by `chssh_feed_input(ctx, buf, len)` and `chssh_get_output(ctx, buf, max)`
- Able to work with edge-triggered (`EPOLLET`), level-triggered, and completion-based (io_uring) models
- Free of assumptions about blocking behavior, threading model, or buffer ownership

## Rationale
The four event mechanisms represent the dominant approaches to high-performance networking in C:
- Completion-based (io_uring)
- Readiness-based with callbacks (libev, libuv)
- Raw readiness with epoll

By explicitly requiring compatibility with all four, we prevent accidental introduction of:
- Hidden callbacks or function pointers
- Blocking operations inside the library
- Assumptions about buffer lifetime or single-threaded use
- State that cannot be driven from an edge-triggered loop

## Consequences
- Any proposed change to the public API or internal state machine must be reviewed against the event-loop compatibility requirement.
- New features (message framing, PostGIS type support, extended query protocol, COPY, etc.) must be exercisable from all four harness styles.
- The examples in `examples/` (when added) act as a living compatibility harness.
- `AGENTS.md` and `ARCHITECTURE.md` list this constraint as a first-class invariant.

## Verification
- Core tests and future examples exercise the same `feed_input` / `get_output` boundary.
- Future ADRs or PRs that touch the state machine must reference this ADR.

This decision ensures the library remains a true reusable state machine rather than becoming tied to any single eventing style.