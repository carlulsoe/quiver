# Plan 009: Assemble and verify the approved audit stack

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: HIGH
- **Depends on**: plans 001-008
- **Category**: integration
- **Planned at**: 2026-09-03

## Approved heads

- Verification/orchestration/persistence chain: `advisor/008-authoritative-session-state` at `c1a581d`
- Proof/report chain: `advisor/007-typed-scalar-redaction` at `17de4bf`
- Runtime safety: `advisor/003-runtime-safety-gaps` at `71e6661`
- Browser reproducibility: `advisor/006-browser-reproducibility` at `b23f033`

## Steps

1. Assemble those four approved heads on an isolated integration branch based on `main`. Preserve the
   reviewed commits/lineage and resolve only conflicts required to combine them.
2. Resolve the known `CampaignSession` seam semantically: persistence's extracted `createRunEvent`
   path must use plan 007's structured/provenance-aware redaction. Keep authoritative control snapshots,
   batched writes, and the public `CampaignSessionOptions` export.
3. Combine README/package/workflow changes from verification, persistence, and managed-browser work.
   Keep pinned Bun/Playwright, frozen verification, browser provisioning, exit codes, and durability docs.
4. Run frozen install, the managed-browser install/launch check, `bun run verify`, secret scanning, and
   `git diff --check`. Inspect the combined diff for dropped files or conflict markers.

## Done criteria

- All approved milestone behavior and tests coexist on one branch.
- The full suite and final whole-stack autoreview against `main` are clean.
- `main` is untouched; the integration branch is ready for the user's merge decision.

## STOP conditions

Stop on a non-trivial product choice, a durability/redaction/safety conflict that cannot preserve both
reviewed guarantees, or any need to rewrite history on `main`.
