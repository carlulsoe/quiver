# Plan 005: Make durable campaign persistence scale without weakening recovery

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Depends on**: plan 004
- **Category**: performance
- **Planned at**: `35a4432`, 2026-09-03

## Why this matters

One logical transition currently causes multiple synchronous fsync-backed records and repeated full
serialization of a state whose history grows throughout the campaign. The fix must reduce write and
clone amplification while preserving write-ahead durability and conservative mutation recovery.

## Current state

- `CampaignSession.dispatch` applies/checkpoints and then records another persisted state event.
- `JsonlCampaignStore.apply` durably appends each action; `checkpoint` appends the complete state.
- `appendDurably` opens, writes, `fsyncSync`s, and closes for each record.
- `runner.ts:64` reads runtime control via `session.checkpoint()`, cloning or checkpointing complete
  state during request admission.
- Existing durability tests cover replay, torn tails, checksums, process locking, and runtime jobs.

## Commands

`bun install --frozen-lockfile`; focused campaign-store/session/runtime tests; a deterministic bounded
write-count/size benchmark test; `bun run verify`.

## Scope

In scope: campaign-store interface/implementations, CampaignSession persistence/telemetry batching,
runtime-control reads, persistence tests, and README durability wording if behavior changes.

Out of scope: a new database, weakening per-action WAL durability before external effects, removing
checksums/locking, changing campaign report schema, or lossy history.

## Steps

1. Add characterization instrumentation/tests that count records, full checkpoints, fsync calls or
   injected durable writes, and log-size growth for a representative campaign sequence. Preserve the
   pre-change proof in test history or commit description.
2. Split a cheap immutable current-state/control read from a full persisted checkpoint. Request
   admission must never serialize/clone the complete history merely to inspect control status.
3. Preserve a flushed action WAL before an effect is treated as committed, but coalesce derived state
   telemetry with its originating transition. Emit full checksum checkpoints at bounded intervals and
   terminal/lifecycle boundaries, with an explicit threshold owned by the store/session.
4. If safe and minimal, hold the descriptor for the store lifetime while retaining exclusive locking;
   do not weaken the required durability flush boundary.
5. Extend recovery tests across pre-checkpoint actions, periodic checkpoints, torn writes, restart,
   pause/cancel/halt, and interrupted mutation. Add a bounded assertion showing record/checkpoint
   growth is no longer proportional to repeated full-history snapshots.

## Done criteria

- Recovery after every tested crash boundary yields the same state or a conservative halt.
- Full-state checkpoint count is bounded by the documented cadence, not every action/event.
- Runtime control reads perform no write and no full-state structured clone.
- Focused tests and `bun run verify` pass; only in-scope files changed.

## STOP conditions

Stop if the proposed batching can lose a mutation marker, requires an on-disk schema migration without
a backward-compatible reader, or cannot prove state equivalence after replay.

## Maintenance notes

Performance tests should assert structural write bounds rather than machine timing. Reviewers must
scrutinize WAL-before-effect ordering more heavily than raw throughput.

