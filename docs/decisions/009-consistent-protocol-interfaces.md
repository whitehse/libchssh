# ADR 009: Consistent Event-Driven Interface for Protocol Modules

**Date**: 2026-06-27  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context
The initial skeleton already uses the modern interface pattern (`chssh_config_t`, `chssh_create_with_config`, `chssh_next_event`, `chssh_event_t`). It is important to record that this style is the required standard going forward.

## Decision
The library shall use (and any future protocol modules shall converge on) the following interface pattern:

```c
typedef struct {
    int event_queue_size;   /* 0 = use sensible default */
} chssh_config_t;

ctx = chssh_create_with_config(role, &config);
chssh_feed_input(ctx, data, len);
int chssh_next_event(ctx, &chssh_event_t event);
size_t chssh_get_output(ctx, buf, max);
void chssh_destroy(ctx);
```

## Rationale
- Reduces cognitive load.
- Enables shared test harnesses and example code.
- Aligns with the "explicit event structures" preference stated in project memory.
- Still allows protocol-specific events inside the `chssh_event_t` union.

## Consequences
- All public functions and the `chssh_event_t` structure follow this style.
- Examples and tests use the `next_event` style.
- Old getter functions (if any) are avoided.

## Verification
- The module exposes `*_config_t`, `*_create_with_config`, and `*_next_event`.
- Existing tests continue to pass.
- New code uses the event-driven style.

This decision ensures a cohesive, predictable API family.