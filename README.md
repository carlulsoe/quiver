# Quiver prototype

> **Throwaway prototype.** This exists to answer one question: can a small,
> bounded Flue agent loop explore and independently validate a vulnerability in
> a local crAPI instance while running from a Bun CLI?

The prototype is intentionally local-only, in-memory, and narrow. It is not a
general-purpose vulnerability scanner and must not be pointed at systems without
explicit authorization.

## Runtime compatibility spike

```sh
bun run spike:flue
```

The prototype is intentionally fixed to `openrouter/z-ai/glm-5.3-flash`.
Because Flue 2.0.3's bundled OpenRouter catalog predates that model, the
prototype registers its current OpenRouter metadata explicitly.

## Run the prototype

This requires Bun, Docker Compose, and an `OPENROUTER_API_KEY` in the
environment.

Start the pinned OWASP crAPI 1.1.5 checkout on loopback port 8888, then run:

```sh
bun run target:up
bun run prototype -- http://127.0.0.1:8888
```

Write the final verdict, metrics, scoped HTTP activity, and Flue tool trace to a
JSON report while suppressing live terminal rendering:

```sh
bun run prototype -- http://127.0.0.1:8888 \
  --quiet \
  --report .prototype/runs/latest.json
```

Run `bun run prototype -- --help` for CLI options.

Stop the target without deleting its database volumes:

```sh
bun run target:down
```

The current target profile supplies a small subset of crAPI's public API
contract. Two independent Flue explorers use live, scope-enforced requests to
find a vehicle-location BOLA candidate. A fresh validator then reproduces the
request and deterministically checks that the authenticated user's identity
differs from the returned vehicle owner and that coordinates were disclosed.

Current hard boundaries:

- Loopback targets only
- GET requests only after a fixed seeded-user login
- Exact-origin enforcement and redirects disabled
- Thirty-request global budget
- 12 KB response cap
- No shell, browser, filesystem, or arbitrary HTTP tools exposed to agents

## Run the evals

The live-model eval suite uses Flue's in-process runtime through a custom
`vitest-evals` harness. It keeps the probabilistic behavior under test while
scoring the final security claim deterministically:

```sh
bun run target:up
bun run evals
```

It evaluates two contracts:

- The explorers must find a candidate that the fresh validator confirms within
  the request budget.
- Given only the authenticated user's own vehicle, the model-backed validator
  must reject it rather than produce a false confirmation.

Run repeated GLM discovery trials when checking reliability. The negative
control still runs once per suite:

```sh
XBOW_EVAL_TRIALS=5 bun run evals:json
```

The JSON report is written to `.prototype/eval-results.json`; inspect it with
`bun run evals:report`. The report includes normalized Flue tool calls and their
results in addition to the deterministic behavioral score.

## Developer loop

The three verification layers stay separate so the common loop remains fast:

```sh
bun run test              # pure state, validation, gateway, CLI, and report tests
bun run test:integration  # live HTTP checks against the local crAPI stack
bun run test:all          # both fast and live HTTP suites
bun run evals             # live GLM agent acceptance suite
bun run verify            # formatting, linting, types, and fast tests
```

Use `bun run test:watch` while changing pure logic. Integration tests cover the
seeded user's safe vehicle and a dynamically discovered cross-owner vehicle;
they do not spend model tokens.

## Observed verdict

On 2026-08-30, Flue 2.0.3 completed real model and tool turns inside Bun 1.4.0
using `openrouter/z-ai/glm-5.3-flash`. Two short-lived explorers independently
tested the local target. A fresh validator confirmed one vehicle-location BOLA
with deterministic cross-owner and coordinate checks. The successful run used
16 of the 30 permitted HTTP requests.

The latest report-producing eval run passed both behavioral contracts and
captured normalized tool activity: discovery confirmed the BOLA in 45.9 seconds
using 15 requests and 18 tool calls; the negative control rejected the seeded
user's own vehicle in 10.5 seconds using 5 requests and 2 tool calls. Both
received a deterministic score of 1.00.
