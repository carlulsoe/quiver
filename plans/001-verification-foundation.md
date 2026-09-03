# Plan 001: Establish a reproducible verification foundation

> Execute this plan completely in an isolated worktree. Do not update `plans/README.md`; the
> reviewer owns it. Stop rather than broadening the product or release process.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none
- **Category**: dependencies, DX, docs
- **Planned at**: `35a4432`, 2026-09-03

## Why this matters

The repository already has strong local checks, but its toolchain floats, the custom lint plugin is
outside TypeScript coverage, no CI enforces the gates, and the CLI's exit code 2 is undocumented.
This milestone makes the existing quality contract reproducible without changing campaign behavior.

## Current state

- `package.json:19-27,36-43` uses unversioned `bunx` and `latest` dev dependencies.
- `tsconfig.json:13` includes only `src` and `scripts`, while `.oxlintrc.json:2-19` executes ten
  repository-owned rules from `tools/oxlint/anti-slop`.
- There is no `.github/workflows` configuration.
- `src/prototype/cli.ts:37-39` returns 1 for failure and 2 for a completed run with no confirmed
  finding, but `src/prototype/cli-options.ts:97-109` does not document exit statuses.
- Match existing Vitest style from `src/prototype/cli-options.test.ts` and repository commit messages
  such as `Add anti-slop lint rules and split large files`.

## Commands

| Purpose | Command | Expected |
|---|---|---|
| Install current base | `bun install --frozen-lockfile` | exit 0, lock unchanged |
| Regenerate intentional lock changes | `bun install` | exit 0 |
| Fast gate | `bun run verify` | exit 0 |
| Secret gate | `bun run security:secrets` | no leaks |

## Scope

In scope: `package.json`, `bun.lock`, `README.md`, `src/prototype/cli-options.ts`,
`src/prototype/cli-options.test.ts`, `.github/workflows/**`, `tsconfig*.json`, and new focused test
fixtures under `tools/oxlint/anti-slop/**`.

Out of scope: campaign runtime behavior, integration target launchers, dependency major upgrades,
release/publish automation, and any weakened lint rule.

## Steps

1. Declare the supported Bun version used by the repository and replace `latest` declarations with
   the versions currently resolved in `bun.lock`. Make scripts use locked local tools; do not upgrade
   unrelated packages. Regenerate the lockfile intentionally.
2. Add a dedicated typecheck/test path for every custom Oxlint plugin source file. Add valid and
   invalid fixtures for all ten rules and make the normal verification command run them.
3. Add CI on pushes and pull requests: pinned Bun setup, `bun install --frozen-lockfile`, and
   `bun run verify`. Add the redacting secret scan in an environment where Docker is available.
   Keep live Docker targets and model evals scheduled/manual rather than blocking every change.
4. Document install prerequisites, the frozen install command, supported Bun version, verification
   tiers, and exit codes 0/1/2 in README and CLI help. Add assertions locking the help text contract.

## Test plan and done criteria

- Plugin fixtures prove every rule both accepts a valid example and rejects an invalid example.
- CLI option/help tests assert the exit-status documentation.
- `bun install --frozen-lockfile`, `bun run verify`, and `bun run security:secrets` pass.
- CI YAML parses and invokes only repository scripts; no mutable action reference is introduced when
  a commit-SHA pin is practical.
- `git diff --name-only 35a4432..HEAD` contains only in-scope files.

## STOP conditions

Stop if the resolved tool versions require source migrations, the plugin cannot be tested without a
new framework dependency, or CI requires credentials/model access for the fast gate. Do not loosen a
lint rule or silently skip a plugin test to make verification pass.

## Maintenance notes

Future toolchain upgrades must update the declared Bun version, exact dev dependencies, lockfile, and
CI together. Keep expensive target/eval gates visibly separate from the deterministic fast gate.

