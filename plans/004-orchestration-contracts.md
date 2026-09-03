# Plan 004: Characterize successful orchestration and exhaust campaign actions

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plan 001
- **Category**: tests, tech debt
- **Planned at**: `35a4432`, 2026-09-03

## Why this matters

Normal verification has no deterministic test that drives a successful campaign through exploration,
validation, budget reclamation, and completion. The action union also compiles when a new action is
handled by neither reducer, creating a silent no-op at the durability boundary.

## Current state

- `runner.test.ts` covers construction failure and terminal/resume exits, not a successful active run.
- `campaign.eval.ts` covers success only with live models and a ten-minute eval timeout.
- `state-actions.ts:15-43` is one union; `state-runtime-reducer.ts:115-116` and
  `state-reducer.ts:108-109` have permissive defaults.
- Follow existing injected model-router patterns in `runner.test.ts`, tool-adapter fakes, and the small
  module convention enforced by the 200-line lint limit.

## Commands

`bun install --frozen-lockfile`; focused runner/state tests; `bun run verify`.

## Scope

In scope: runner/executor construction seams needed for deterministic tests, runner tests, campaign
action type partitions, both reducer ownership boundaries, and focused reducer tests.

Out of scope: changing public campaign outcomes, model routing policy, live eval scoring, or rewriting
executors merely to simplify mocks.

## Steps

1. Introduce the narrowest dependency-injection seam that lets a test replace agent-runtime startup
   and exploration/validation executors while retaining the real CampaignSession, reducer, budget,
   and completion orchestration.
2. Add one deterministic successful campaign test covering discovery, accepted finding, independent
   validation, budget reclaim, all jobs finished, final `complete`, and aggregate history. Assert the
   ordering/invariants that matter rather than private call noise.
3. Partition runtime-owned and campaign-owned actions so each switch is exhaustively checked with
   `never`. Preserve the persisted action wire shapes.
4. Add a compile-time/table-driven ownership assertion and behavioral reducer tests for representative
   safety, budget, finding, and history actions.

## Done criteria

- The successful orchestration path runs under `bun run test` without network, browser, model, or
  Docker access.
- Adding an unowned action demonstrably fails type-checking rather than becoming a no-op.
- Existing checkpoint/recovery tests and `bun run verify` pass; only in-scope files changed.

## STOP conditions

Stop if the test requires a production-only fake branch, changes Flue lifecycle semantics, or action
partitioning changes serialized action discriminants.

## Maintenance notes

Keep the happy-path test at the orchestration contract level. Any new campaign action must be owned by
exactly one exhaustive reducer.

