# Quiver audit implementation plans

Generated from the whole-repository audit at `35a4432` on 2026-09-03. Executors work in
isolated worktrees. The reviewer owns this index and runs autoreview after every milestone.

## Execution order and status

| Plan | Milestone | Findings covered | Priority | Depends on | Status |
|---|---|---|---|---|---|
| 001 | Reproducible verification foundation | DX-01, DX-02, DEPENDENCIES-01, DOCS-01 | P1 | — | DONE — `0dfa69b`, autoreview clean |
| 002 | Bind proofs and redact derived evidence | CORRECTNESS-01, SECURITY-01 | P1 | — | DONE as stack `1bda22d` + 007 |
| 003 | Close runtime safety policy gaps | CORRECTNESS-02, SECURITY-03 | P1 | — | DONE — `71e6661`, autoreview clean |
| 004 | Characterize orchestration and exhaust actions | TEST-01, TECHDEBT-01 | P1 | 001 | DONE — `ef54e21`, autoreview clean |
| 005 | Make durable persistence scale | PERFORMANCE-01 | P1 | 004 | DONE as stack `eccd92e` + 008 |
| 006 | Make browser execution reproducible | DEPENDENCIES-02 | P2 | 001 | DONE — `b23f033`, autoreview clean |
| 007 | Preserve typed report fields during scalar redaction | M002 review regression | P1 | 002 | DONE — `17de4bf`, autoreview clean |
| 008 | Synchronize session state after authoritative writes | M005 review regression | P1 | 005 | DONE — `c1a581d`, autoreview clean |
| 009 | Assemble and verify approved audit stack | Integration of 001-008 | P1 | 001-008 | DONE — `aefc042`, autoreview clean |

## Dependency notes

- Plans 001, 002, and 003 may execute in parallel from `35a4432`.
- Plan 004 starts after 001 so its new orchestration test runs under the pinned verification gate.
- Plan 005 starts after 004 because persistence batching needs whole-campaign characterization.
- Plan 006 starts after 001 so it extends the same pinned toolchain/install contract.

## Review and landing policy

For each milestone: install with the frozen lockfile, run focused tests, run `bun run verify`, run
the global autoreview helper against the milestone branch, vet every reported finding, and rerun
tests plus autoreview after any accepted review fix. A milestone is DONE only after a clean review.

## Deliberately not included

- Direction options from the audit are product proposals, not defects selected for implementation.
- Whole-store encryption/minimization, public-facade type-cycle cleanup, and mutable public state were
  considered but were not in the final twelve-item findings list requested for implementation.
