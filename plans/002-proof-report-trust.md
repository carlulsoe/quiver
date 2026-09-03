# Plan 002: Bind proof evidence and redact derived values

> Execute in an isolated worktree and touch only the listed proof/report surfaces. The deterministic
> predicate remains authoritative; do not replace checks with LLM judgment.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: bug, security
- **Planned at**: `35a4432`, 2026-09-03

## Why this matters

An affected endpoint currently only has to occur somewhere in a reproduction, so unrelated indexed
evidence can confirm the claim. Separately, selected sensitive values lose their JSON-pointer context
when copied into generic `actual` fields, allowing report redaction to miss them.

## Current state

- `proof-operation.ts:24-28` uses `reproduction.some`, while access/data handlers consume explicit
  indexes without binding those indexes to `finding.endpoint` and `finding.method`.
- `proof-json.ts:27-34,37-70` copies pointer-selected values into `ProofCheck.actual`.
- `security/redaction.ts:8-23` redacts primitives by current property name, and
  `report-markdown-findings.ts:71-88` prints checks and observations.
- Follow test organization in `proof-policies.test.ts` and the `proof-*.cases.ts` packs; follow report
  sentinel-secret assertions in `report.test.ts`.

## Commands

`bun install --frozen-lockfile`; focused proof/report Vitest files; then `bun run verify`. All exit 0.

## Scope

In scope: `src/prototype/proof-operation.ts`, relevant `proof-handlers-*.ts`, `proof-json.ts`, proof
types when required, `security/redaction.ts`, report creation/rendering, and focused proof/report tests.

Out of scope: predicate/category compatibility, target policies, report schema version unless a shape
change is unavoidable and explicitly justified, or removal of useful non-sensitive evidence.

## Steps

1. Identify every proof predicate that selects one or more reproduction indexes. Require each
   proof-bearing request that represents the claimed vulnerable operation to match the finding method
   and endpoint. Preserve legitimate multi-request control/probe semantics.
2. Add negative tests with a matching decoy request plus unrelated successful evidence for
   cross-principal access, cross-principal data exposure, unauthenticated success, and any sibling
   indexed predicate sharing the bug class. Existing valid proofs must stay confirmed.
3. Preserve sensitivity metadata or sanitize selected values before field-name context is discarded.
   Cover `actual`, differential strings, reviewer/evidence narrative, redirect locations, raw
   observations, JSON output, and Markdown output with sentinel values. Do not redact ordinary IDs,
   statuses, or benign evidence.

## Done criteria

- Decoy-operation tests reject while existing valid proof packs pass.
- No sentinel credential value appears anywhere in `JSON.stringify(createRunReport(...))` or rendered
  Markdown, including copied proof-check values.
- Focused tests and `bun run verify` pass; only in-scope files changed.

## STOP conditions

Stop if the correct operation binding is ambiguous for a predicate, or safe redaction requires
removing all raw replay evidence. Report the predicate/field and required contract decision.

## Maintenance notes

Any future proof selector must declare which request is the affected operation. Any response-derived
value copied into a generic field must retain enough provenance for redaction.

