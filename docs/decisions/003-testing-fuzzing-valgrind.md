# ADR 003: Mandatory Testing, Fuzzing, and Valgrind for Core Library Changes

**Date**: 2026-06-27  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context
The library is a security-sensitive, pure state machine that will be driven by untrusted network input (CHSSH protocol messages) from many different event loops (liburing, libev, libuv, epoll). Changes to the core (`src/chssh.c`, `include/chssh.h`, message parsing, XML message parsing, CHSSH message framing) carry high risk of memory safety bugs, parsing errors, and protocol violations.

## Decision
All changes to the core library **must** pass the following before being considered complete:

1. **Unit / Integration Tests**
   - All new functionality must have corresponding tests in `tests/`.
   - Existing tests must continue to pass (`ctest`).

2. **Fuzzing**
   - A libFuzzer (or AFL++) target (`fuzz_chssh`) should exist and be run on any non-trivial change to message parsing, message parsing or framing.
   - Fuzzing runs of at least several million iterations with no new crashes or sanitizer violations are required for parser changes.

3. **Valgrind**
   - All tests must pass under Valgrind (`valgrind --leak-check=full --error-exitcode=1`).
   - No new memory leaks, use-after-free, or invalid reads/writes introduced.

## Rationale
- The library is intended to be embedded in high-performance database clients/servers handling untrusted traffic.
- The event-loop harnesses demonstrate that the same core code will be exercised in very different ways.
- Requiring fuzzing + Valgrind raises the bar for memory safety and protocol correctness, especially around binary data and PostGIS geometry payloads.

## Consequences
- CMake should expose fuzzing and valgrind targets when implemented.
- Any PR or agent-generated change touching the core parser or message framing must include evidence of fuzzing runs and a clean Valgrind report.
- Test coverage is now part of the Definition of Done in `AGENTS.md`.

## Verification
- `ctest`
- Future `./build/fuzz_chssh` (libFuzzer) or AFL++ campaign
- `ctest -D ExperimentalMemCheck` or direct `valgrind` invocation on the test binary

This policy is recorded so future agents and contributors understand the quality bar for the core library.