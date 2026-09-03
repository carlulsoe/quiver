# Plan 008: Synchronize session state after authoritative store writes

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: MED
- **Depends on**: plan 005 revision commit `eccd92e`
- **Category**: correctness, durability
- **Planned at**: autoreview follow-up, 2026-09-03

## Why this matters

Plan 005 made control admission read the authoritative store, but `CampaignSession` still reduces its
own cached state independently after writes. An out-of-band durable pause/cancel/halt can therefore be
enforced correctly while a later event, callback, or returned run exposes stale control state.

## Scope

In scope: `CampaignStore` write return/current-state contract, both store implementations,
`CampaignSession` cache synchronization, and focused tests. Out of scope: polling, a new control API,
full-state cloning on admission, or changing WAL/checkpoint ordering.

## Steps

1. Give store writes a non-checkpointing way to return the authoritative resulting state without
   serializing or cloning complete history on the request-admission path.
2. After every session write (`dispatch`, `record`, and history/mission updates), replace the session
   cache with the authoritative store result.
3. Test out-of-band pause/cancel/halt followed by history finalization and callbacks. Assert session
   state and persisted state agree and the synchronization adds no durable write/checkpoint beyond the
   intended action.

## Done criteria

- Store, session, callbacks, and returned-run control state agree after external control actions.
- Control reads remain zero-write and do not full-clone history.
- WAL ordering, checkpoint cadence, focused recovery tests, full verification, and autoreview pass.

## STOP conditions

Stop if synchronization requires returning mutable store internals to arbitrary callers, weakening
durability, or cloning full history for each admission check.
