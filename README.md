# Quiver

Quiver is a bounded Bun CLI for running Flue security campaigns against
authorized local web targets. Given a loopback URL and an HTTP request budget,
Quiver exercises the live application in Chromium, records its REST traffic,
merges any supplied OpenAPI definition, and gives explorers the resulting attack
surface. A fresh validator independently replays each finding, while
code-owned proof predicates—not an LLM decision—determine confirmation.

The campaign engine is target-agnostic. A small `TargetProfile` supplies target
setup such as authentication, allowed setup operations, and explicitly denied operations. The CLI ships
profiles for OWASP crAPI, Broken Crystals, OWASP VulnerableApp, VAmPI's vulnerable
and secure modes, and a randomized held-out target; campaign state, mapping,
deterministic validation, and reporting contain no target route inventory or
vulnerability-specific proof code.

This is not a general-purpose vulnerability scanner. Only test systems you own
or are explicitly authorized to assess.

## Run a campaign

This requires Bun, Chromium, Docker Compose, and an `OPENROUTER_API_KEY`. The model
is fixed to `openrouter/z-ai/glm-5.3-flash`.

Start the pinned OWASP crAPI 1.1.5 checkout and run a campaign:

```sh
bun run target:up
bun run campaign -- http://127.0.0.1:8888 --budget 36
```

The URL is the browser mapping start and may include a path. `--budget` is the
total HTTP request budget. Quiver reserves one third for independent validation and gives
the remainder to exploration. Explorers share their portion; the validator gets
a fresh scoped target and authenticated session. Any exploration allowance left
unused is reclaimed for validation.

Supply an OpenAPI JSON or YAML document and assessment notes when the application
does not exercise its complete API during the initial browser session:

```sh
bun run campaign -- http://127.0.0.1:8888 \
  --openapi ./openapi.yaml \
  --context ./assessment-context.md \
  --budget 36
```

OpenAPI operations are merged with browser-observed methods and paths. Context is
shown to explorers as target data, not treated as tool instructions. Set
`QUIVER_BROWSER_PATH` when Chromium is not installed in a standard location.

Write the complete finding set, outcomes, budget usage, HTTP activity, and Flue
tool trace to JSON without the live terminal view:

```sh
bun run campaign -- http://127.0.0.1:8888 \
  --budget 36 \
  --quiet \
  --report .prototype/runs/latest.json
```

Use a `.md` path for an evidence-first handoff with campaign metrics,
independent validation evidence, and copyable REST `curl` reproductions:

```sh
bun run campaign -- http://127.0.0.1:8888 \
  --budget 36 \
  --quiet \
  --report .prototype/runs/latest.md
```

Run `bun run campaign -- --help` for all options. Stop crAPI without deleting its
database volumes with `bun run target:down`.

## Additional test targets

All launchers pin an upstream source revision, and the campaign still enforces
its loopback-only target boundary. Broken Crystals is the larger end-to-end target:

```sh
bun run target:broken-crystals:up
bun run campaign -- --profile broken-crystals --budget 60
bun run target:broken-crystals:down
```

OWASP VulnerableApp is built locally so its native DAST comparator is available.
The `scoreVulnerableAppBenchmark` adapter in
`src/evals/vulnerableapp-benchmark.ts` submits confirmed endpoints, methods, and
CWEs and reports native coverage, precision, misses, and unmatched findings as
false positives.

```sh
bun run target:vulnerableapp:up
bun run campaign -- --profile vulnerableapp --budget 60
bun run target:vulnerableapp:down
```

VAmPI starts secure and vulnerable configurations together. Run identical
campaign settings against each, then pass the confirmed finding sets to
`compareVampiPair` in `src/evals/vampi-oracle.ts`. Vulnerable-only confirmations
are differential true positives; secure-instance confirmations reveal persistent
vulnerabilities or false positives.

```sh
bun run target:vampi:up
bun run campaign -- --profile vampi-vulnerable --budget 42
bun run campaign -- --profile vampi-secure --budget 42
bun run target:vampi:down
```

## Campaign behavior

Explorers begin with `map_attack_surface`. A headless Chromium session records
same-origin runtime requests, including methods and likely authentication, while
following same-origin links. Supplied OpenAPI operations are merged with that
runtime evidence, including summaries and templated paths.
Explorers may submit multiple findings and continue after each submission.
Findings carry severity, CWE, impact, mitigation, an ordered reproduction plan
containing exact REST methods, bodies, headers, and authentication mode, and one
structured proof predicate. The predicates prove cross-principal access, unauthenticated
successful access, or specifically declared exposed fields. BOLA proofs require
different actor and resource-owner identities plus concrete impact fields in a
successful access response.

A shared campaign ledger coalesces duplicate concurrent requests, distinguishes
anonymous from authenticated observations, and exposes tested operations and
accepted findings to every explorer. A small adaptive coordinator claims
uncovered operations for individual explorers and uses incoming status evidence to
assign the opposite authentication boundary next. Duplicate work therefore
reuses the first observation instead of consuming more request budget.

Quiver deduplicates findings by vulnerability category and normalized endpoint.
For example, two different vehicle UUIDs affected by the same object-level
authorization flaw become one finding. The validator replays every unique
finding. Its LLM supplies an informational review, but cannot set the outcome:
the declared predicate runs over raw replay observations and is authoritative.
If the validation budget is insufficient, the report leaves the remaining
findings explicitly unvalidated.

Current hard boundaries:

- Loopback HTTP(S) targets only
- Browser and agent REST traffic may use GET, HEAD, POST, PUT, PATCH, DELETE, or OPTIONS
- Agent state-changing requests must come from the browser/OpenAPI map or profile setup allowlist
- Profiles may deny operations known to have unwanted side effects; the crAPI profile
  blocks its database- and filesystem-mutating mechanic report handlers
- Exact-origin enforcement with redirects disabled
- Shared campaign budget with a reserved validation portion
- 12 KB cap for agent-visible responses
- No shell, browser, filesystem, or arbitrary network tools exposed directly to agents

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

The campaign contract requires at least 50% benchmark coverage, 100%
conservative precision, no safe-control or unscored confirmations, no agent
failures, deterministic replay of every submission, and strict request-budget
compliance. Unscored confirmations remain visible for human ground-truth review
but count against precision rather than escaping false-positive accounting.

Run repeated GLM trials and inspect the generated report with:

```sh
XBOW_EVAL_TRIALS=10 bun run evals:json
bun run evals:report
```

Each trial runs in a fresh process because Flue permits one runtime lifecycle
per process. Quiver writes merged viewer input to
`.prototype/eval-results.json` and publishable aggregate metrics to
`.prototype/eval-summary.json` and `.prototype/eval-summary.md`: success rate,
mean coverage, false-positive rate, requests per true positive, duration, token
usage, and approximate model cost.

Trials are sequential by default. Set `XBOW_EVAL_CONCURRENCY=2` to use two
isolated worker processes when the local target and model provider can support
the extra load.

See the committed [10-trial crAPI results](docs/showcase/crapi-10-trial-results.md)
for the full strict-pass baseline and the
[held-out deterministic proof report](docs/showcase/held-out-sample.md) for the
randomized target showcase.

## Randomized held-out target

The bundled Ledgerly fixture gives the same engine a substantially different,
seeded target without a public answer key. Its frontend route namespace, asset
name, principal IDs, object IDs, and impact canary change with the seed. It
contains a canary-backed cross-principal record and a neighboring authorization
control.

Start it in one terminal with a fresh random seed:

```sh
bun run target:held-out
```

Then run the same campaign engine in another terminal:

```sh
bun run campaign -- \
  --profile held-out \
  --budget 30 \
  --report .prototype/runs/held-out.md
```

Set `QUIVER_HELD_OUT_SEED` when a reproducible showcase run is useful. The
generated Markdown report includes severity, CWE, impact, mitigation, raw replay
responses, predicate checks, copyable requests, route coverage, model cost, and
an anchored chronological trace.

## Developer loop

```sh
bun run test              # fast campaign, benchmark, mapper, CLI, and report tests
bun run test:integration  # live crawl and authentication checks against crAPI
bun run test:all          # fast and live HTTP suites
bun run evals             # isolated live GLM trial (set XBOW_EVAL_TRIALS to repeat)
bun run verify            # formatting, linting, types, and fast tests
```
