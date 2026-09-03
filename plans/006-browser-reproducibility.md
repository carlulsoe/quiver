# Plan 006: Make the browser compatibility boundary reproducible

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plan 001
- **Category**: dependencies
- **Planned at**: `35a4432`, 2026-09-03

## Why this matters

Browser mapping and proof semantics depend on Playwright interception/navigation behavior, but Quiver
currently launches whichever unversioned Chromium exists on the machine. The default developer and CI
path should use a browser version matched to the pinned Playwright client while retaining an explicit
advanced override.

## Current state

- `package.json:32` declares `playwright-core` with a range and no managed browser package.
- `attack-surface-scope.ts:55-75` probes four system locations.
- `attack-surface.ts`, `browser-effect.ts`, and `browser-state-transition.ts` share the central launch
  helper and optional `QUIVER_BROWSER_PATH` override.
- README calls Chromium an unversioned prerequisite.

## Commands

`bun install`; frozen reinstall; focused browser tests; `bun run verify`. Run the repository browser
tests using the managed executable when the environment supports the download.

## Scope

In scope: exact Playwright/browser dependencies and lockfile, centralized browser resolution/launch,
browser tests, CI browser provisioning, and README setup/override documentation.

Out of scope: changing browser security routing, navigation decisions, headless policy, adding multiple
browser engines, or silently accepting an incompatible override.

## Steps

1. Consult the installed dependency documentation/types and official Playwright documentation. Choose
   the supported managed-Chromium mechanism that exactly matches the pinned Playwright release; do not
   guess an external Chrome compatibility range.
2. Make that managed executable the default. Retain `QUIVER_BROWSER_PATH` as an explicit advanced
   override and surface the launched browser version/path in startup diagnostics or errors without
   leaking unrelated environment data.
3. Make CI provision/cache the matching browser deterministically. Document install size and the
   offline/system-browser override.
4. Add tests for default resolution, override resolution, missing browser, launch failure, and the
   existing request-interception/proof flows.

## Done criteria

- A frozen install plus documented browser-install command selects a Playwright-matched Chromium.
- CI and local default paths agree; the override remains explicit and test-covered.
- Browser-focused tests and `bun run verify` pass; only in-scope files changed.

## STOP conditions

Stop if Bun cannot install the official managed-browser package reproducibly, the solution requires a
large deployment-policy choice, or existing environments would silently switch browser behavior
without an escape hatch.

## Maintenance notes

Upgrade Playwright client, managed browser, CI cache key, and documented install command together.

