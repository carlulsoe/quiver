# Quiver prototype

Quiver is a bounded Bun CLI for experimenting with Flue security agents against
authorized local web targets. Given a loopback URL, explorers crawl the live
frontend, derive route candidates from links and compiled JavaScript, exercise
read-only requests, and submit concrete findings to a fresh validator.

The orchestration is target-agnostic. Target-specific authentication,
objectives, and deterministic proof live behind a small `TargetProfile` adapter.
The current CLI selects the OWASP crAPI profile; adding a comparable local target
does not require changing the crawler, agents, run state, reporting, or eval
harness.

This remains a prototype, not a general-purpose vulnerability scanner. Only test
systems you own or are explicitly authorized to assess.

## Run it

This requires Bun, Docker Compose, and an `OPENROUTER_API_KEY`. The model is fixed
to `openrouter/z-ai/glm-5.3-flash`.

Start the pinned OWASP crAPI 1.1.5 checkout on loopback port 8888:

```sh
bun run target:up
bun run prototype -- http://127.0.0.1:8888
```

The supplied URL is the crawl start. A path is allowed, so the same CLI can start
from a specific application surface:

```sh
bun run prototype -- http://127.0.0.1:8888/dashboard
```

Write a structured report without the live terminal view:

```sh
bun run prototype -- http://127.0.0.1:8888 \
  --quiet \
  --report .prototype/runs/latest.json
```

Run `bun run prototype -- --help` for CLI options. Stop crAPI without deleting
its database volumes with `bun run target:down`.

## Architecture and boundaries

`ScopedTarget` is the deep boundary around HTTP. It owns exact-origin scope,
the shared request budget, redirects, timeouts, response caps, authenticated
session headers, and a cached same-origin crawl. The crawler follows frontend
documents and derives routes from ordinary links, quoted paths, and JavaScript
string composition. Agents receive that live map through `crawl_target`; there
is no supplied crAPI API inventory.

The crAPI profile supplies only the details the generic engine cannot infer:

- The assessment objective
- An opaque seeded-user authentication procedure
- A whitelist for the login POST
- Deterministic BOLA validation and its negative control

Current hard boundaries:

- Loopback HTTP(S) targets only
- Agent traffic is GET-only; a profile may whitelist exact setup POSTs
- Exact-origin enforcement with redirects disabled
- Thirty-request shared default budget
- 12 KB response cap for agent-visible requests
- No shell, browser, filesystem, or arbitrary network tools exposed to agents

## Evals

The live-model suite uses Flue through a `vitest-evals` harness:

```sh
bun run target:up
bun run evals
```

It checks two behavioral contracts:

- Explorers must begin from live crawl discovery, find a candidate, and obtain a
  deterministic confirmed verdict within budget.
- Given the authenticated user's own vehicle, the model-backed validator must
  reject the claim rather than create a false confirmation.

The discovery contract explicitly requires `crawl_target`, `propose_candidate`,
`reproduce_candidate`, and `submit_verdict` in the trace. A separate live HTTP
integration test proves that the generic crawler derives crAPI's relevant routes
from the served frontend bundle.

Run repeated GLM discovery trials with:

```sh
XBOW_EVAL_TRIALS=5 bun run evals:json
```

Inspect `.prototype/eval-results.json` with `bun run evals:report`.

## Developer loop

```sh
bun run test              # fast crawler, state, target-profile, CLI, and report tests
bun run test:integration  # live crawl and deterministic proof against local crAPI
bun run test:all          # fast and live HTTP suites
bun run evals             # live GLM agent acceptance suite
bun run verify            # formatting, linting, types, and fast tests
```

Use `bun run test:watch` for the fast loop. The live layers remain separate so
ordinary refactoring does not spend model tokens.
