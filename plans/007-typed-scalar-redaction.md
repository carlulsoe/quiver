# Plan 007: Preserve typed report fields during scalar credential redaction

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: MED
- **Depends on**: plan 002 revision commit `1bda22d`
- **Category**: security, correctness
- **Planned at**: autoreview follow-up, 2026-09-03

## Why this matters

Plan 002's final autoreview found that correlating credential scalars by their string form can replace
unrelated numeric and boolean report fields with the string `[REDACTED]`. That violates the declared
report/proof schemas and can change downstream truthiness while attempting to prevent derived-text
leaks.

## Scope

In scope: credential correlation/redaction and focused proof/report tests. Out of scope: operation
binding, report schema changes, or weakening redaction of credential-labelled fields and textual
copies.

## Steps

1. Keep collecting numeric and boolean credential scalars so their textual copies can be removed.
2. Never globally replace unrelated numeric or boolean leaves based only on scalar equality. Preserve
   their original types and values unless their own field/path provenance is credential-sensitive.
3. Remove field-name exceptions introduced only to compensate for global scalar replacement.
4. Add regressions with credential values equal to status codes, counters, and booleans. Assert the
   credential fields and prose copies are redacted while unrelated structured values remain typed and
   unchanged.

## Done criteria

- Direct proof output and full reports redact credential-labelled values and derived textual copies.
- Unrelated numbers/booleans retain their type and value.
- Focused tests, `bun run verify`, `git diff --check`, and autoreview against plan 002 pass.

## STOP conditions

Stop if the fix requires changing the persisted report schema or retaining a known credential in
rendered text.
