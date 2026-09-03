# Plan 003: Close reset-mutation and denied-route safety gaps

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED-HIGH
- **Depends on**: none
- **Category**: bug, security
- **Planned at**: `35a4432`, 2026-09-03

## Why this matters

Validation reset hooks run with setup access, so their state-changing requests bypass the durable
mutation marker and may be repeated after a crash. Denied routes are compared as raw paths even
though allow-policy paths are canonicalized, leaving router-equivalent aliases outside the deny set.

## Current state

- `verification-engine.ts:85-96` calls `prepareValidation` inside `runProfileSetup`.
- `validation-executor.ts:34-42` skips mutation tracking for every request labeled `setup`.
- `state-runtime-reducer.ts:120-132` requeues an interrupted state-changing job unless
  `mutationStarted` was persisted.
- `scoped-target-state.ts:84-86` stores raw deny keys; `scoped-target-policy.ts:111-112` uses exact
  membership while `operationAllowed` canonicalizes paths.
- Use crash/recovery patterns in `campaign-store-runtime.test.ts` and path-policy patterns in
  `scoped-target-policy.test.ts` / `scoped-target-security.test.ts`.

## Commands

`bun install --frozen-lockfile`; focused runtime/verification/scoped-target tests; `bun run verify`.

## Scope

In scope: validation reset execution and request-event metadata, durable job mutation tracking,
scoped-target path canonicalization/denial checks, and focused tests.

Out of scope: widening target scope, allowing DELETE proofs, changing authentication setup semantics,
changing configured deny lists, or weakening crash quarantine.

## Steps

1. Distinguish authentication setup requests from validation reset requests without granting reset
   hooks broader network access. Before the first non-read-only reset request, durably mark the active
   state-changing validation job as mutation-started.
2. Add a deterministic crash/recovery test immediately after the reset request event. Resume must
   mark the job interrupted and halt for manual target review; read-only/auth setup recovery remains
   retryable as before.
3. Reuse one fail-closed canonical-operation-path implementation for deny setup and comparison.
   Normalize method case, encoded segments, and trailing slash consistently, rejecting malformed or
   ambiguous encodings.
4. Test exact, encoded, and trailing-slash variants plus near-neighbor paths. Prove configured crAPI
   mechanic-report denials cannot be bypassed while normal GET routes remain available.

## Done criteria

- Reset mutations are marked before transport and quarantined after simulated interruption.
- Authentication setup does not spuriously mark a validation mutation.
- All router-equivalent variants of a denied operation are denied; neighbors are not.
- Focused tests and `bun run verify` pass; only in-scope files changed.

## STOP conditions

Stop if target routers demonstrably disagree on canonicalization, if a reset request cannot be tied
to an active job, or if the change would classify authentication login as proof mutation.

## Maintenance notes

Every request context capable of changing target state must declare whether it belongs to
authentication, reset, discovery, or proof replay. Deny matching must stay at least as strict as allow
matching.

