# Quiver

Quiver is a bounded Bun CLI for running read-only Flue security campaigns against
authorized local web targets. Given a loopback URL and an HTTP request budget,
explorers crawl the live frontend, derive routes from links and compiled
JavaScript, test concrete hypotheses, and submit every distinct vulnerability
they can support. A fresh validator independently replays each finding.

The campaign engine is target-agnostic. A small `TargetProfile` supplies target
setup such as authentication and narrowly allowed setup requests. The current
CLI selects the OWASP crAPI profile; the campaign state, crawler, agents,
validation, reporting, and eval harness contain no crAPI route inventory or
vulnerability-specific proof code.

This is not a general-purpose vulnerability scanner. Only test systems you own
or are explicitly authorized to assess.

## Run a campaign

This requires Bun, Docker Compose, and an `OPENROUTER_API_KEY`. The model is fixed
to `openrouter/z-ai/glm-5.3-flash`.

Start the pinned OWASP crAPI 1.1.5 checkout and run a campaign:

```sh
bun run target:up
bun run campaign -- http://127.0.0.1:8888 --budget 36
```

The URL is the crawl start and may include a path. `--budget` is the total HTTP
request budget. Quiver reserves one third for independent validation and gives
the remainder to exploration. Explorers share their portion; the validator gets
a fresh scoped target and authenticated session. Any exploration allowance left
unused is reclaimed for validation.

Write the complete finding set, outcomes, budget usage, HTTP activity, and Flue
tool trace to JSON without the live terminal view:

```sh
bun run campaign -- http://127.0.0.1:8888 \
  --budget 36 \
  --quiet \
  --report .prototype/runs/latest.json
```

Use a `.md` path for an evidence-first handoff with campaign metrics,
independent validation evidence, and copyable read-only `curl` reproductions:

```sh
bun run campaign -- http://127.0.0.1:8888 \
  --budget 36 \
  --quiet \
  --report .prototype/runs/latest.md
```

Run `bun run campaign -- --help` for all options. Stop crAPI without deleting its
database volumes with `bun run target:down`.

## Campaign behavior

Explorers begin with `crawl_target`; there is no supplied endpoint list. Static
frontend analysis associates routes with observed GET call sites, likely
authentication, and collection routes that may supply dynamic identifiers.
Explorers may submit multiple findings and continue after each submission.
Findings carry an ordered reproduction plan containing only anonymous or
authenticated GET requests.

A shared campaign ledger coalesces duplicate concurrent requests, distinguishes
anonymous from authenticated observations, and exposes tested routes and
accepted findings to every explorer. Duplicate work therefore reuses the first
observation instead of consuming more request budget.

Quiver deduplicates findings by vulnerability category and normalized endpoint.
For example, two different vehicle UUIDs affected by the same object-level
authorization flaw become one finding. The validator replays every unique
finding and records it as confirmed or rejected. If the validation budget is
insufficient, the report leaves the remaining findings explicitly unvalidated.

Current hard boundaries:

- Loopback HTTP(S) targets only
- Agent traffic is GET-only; a profile may whitelist exact setup POSTs
- Profiles may deny GET routes known to have side effects; the crAPI profile
  blocks its database- and filesystem-mutating mechanic report handlers
- Exact-origin enforcement with redirects disabled
- Shared campaign budget with a reserved validation portion
- 12 KB cap for agent-visible responses
- No shell, browser, filesystem, or arbitrary network tools exposed to agents

## Evals

The live-model suite uses Flue through a `vitest-evals` harness:

```sh
bun run target:up
bun run evals
```

The eval-only [crAPI read-only benchmark](src/evals/crapi-read-only-benchmark.md)
is grounded in the pinned target source and official OWASP challenge material.
It scores unique true positives, explicit safe-control false positives, coverage,
precision, missed cases, novel unscored findings, and requests per true positive.
The answer key is not imported by the runtime campaign or target profile.

The campaign contract requires at least one grounded benchmark finding, no
confirmed safe-control claims, independent replay of every submission, and
strict request-budget compliance. The runtime has no dedicated BOLA mode or
negative-control scenario.

Run repeated GLM trials and inspect the generated report with:

```sh
XBOW_EVAL_TRIALS=5 bun run evals:json
bun run evals:report
```

## Developer loop

```sh
bun run test              # fast campaign, benchmark, crawler, CLI, and report tests
bun run test:integration  # live crawl and authentication checks against crAPI
bun run test:all          # fast and live HTTP suites
bun run evals             # live GLM campaign acceptance suite
bun run verify            # formatting, linting, types, and fast tests
```
