# ADR 001: Agent-Ready Documentation Scaffold

**Date**: 2026-06-27

**Status**: Accepted

**Context**:
The repository is being initialized as a pure C, system-call-free, callback-free state-machine library for the CHSSH protocol, following the patterns and philosophy of the sibling project shaggy/libhttp2. To enable effective collaboration with coding agents (Hermes, Claude Code, etc.) from day one, the repo must provide progressive-disclosure documentation: concise entry point (AGENTS.md), architecture codemap (ARCHITECTURE.md), domain context (DOMAIN.md), and decision history (ADRs).

**Decision**:
Adopt the agent-ready scaffold (inspired by Damian Galarza's agent-ready skill and the shaggy project structure):
- Create AGENTS.md as the single source of truth for agents (key commands, rules, DoD).
- Create CLAUDE.md as symlink to AGENTS.md for compatibility.
- Create ARCHITECTURE.md describing module boundaries, plumbing model, invariants, deliberate absences.
- Create docs/ structure with README.md index, DOMAIN.md glossary, and decisions/ subdirectory.
- Record this decision as the first ADR.
- Follow shaggy conventions: CMake, strict warnings, dialectic testing, event-driven next_event API, config structs, no syscalls/callbacks in core.

**Consequences**:
- Agents consulting AGENTS.md will immediately understand build/test commands, operating rules, and current status.
- Architecture and domain assumptions are explicit and reviewable.
- Future changes must update relevant docs/ADRs.
- Maintains alignment with "core as plumbing" and explicit event structures preferred by the user.
- No impact on code yet; pure documentation and repo hygiene.

**References**:
- shaggy/AGENTS.md, ARCHITECTURE.md
- Damian Galarza agent-ready skill (https://www.damiangalarza.com/agent-ready/)
- User memory: explicit event structures, configurable config structs, plumbing philosophy, dialectic testing, pure C, strict module separation.