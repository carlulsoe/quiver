# Quiver

Quiver is a bounded Bun CLI for running Flue security campaigns against
authorized local web targets. Given a loopback URL and an HTTP request budget,
Quiver exercises the live application in Chromium, records its REST traffic,
merges any supplied OpenAPI definition, and gives a coordinated worker fleet the resulting attack
surface. A persistent decision engine retains campaign memory while short-lived generalists and
specialists turn over. Fresh validators independently replay findings as exploration continues, while
code-owned proof predicates—not an LLM decision—determine confirmation.

The campaign engine is target-agnostic. A declarative `TargetManifest` supplies scope,
identities, authentication, protected operations, and explicitly denied operations. A thin
`TargetProfile` adapter exposes that manifest to the runtime. The CLI ships
profiles for OWASP crAPI, Broken Crystals, OWASP VulnerableApp, VAmPI's vulnerable
and secure modes, and a randomized held-out target; campaign state, mapping,
deterministic validation, and reporting contain no target route inventory.
Target-owned policies bind higher-impact validators to specific operations and
synthetic fixtures, while the shared engine contains vulnerability-specific
validation logic.

## Target manifests and principals

Each manifest declares anonymous access plus any independently authenticated principals that a
campaign may compare. Quiver has stable actor references for user A (`ordinary-user`), user B
(`second-user`), and administrator (`privileged-user`). The role and display label remain explicit in
the manifest, so a target may use different application usernames without changing findings or
replay data.

Authentication is data rather than target-specific setup code. The built-in adapters cover bearer or
custom header tokens, HTTP/browser cookies, and login responses that must be materialized into browser
headers, storage, or cookies. Login and refresh exchanges are restricted to `scope.setupOperations`,
charged to the same campaign request budget as every other target request, and may read credentials
only from a declared response header, JSON pointer, literal, or environment reference. Expiring tokens
are refreshed per actor with concurrent refreshes coalesced.
Browser-state strings may interpolate credentials with `{{credential}}` and environment-backed
identity metadata with `{{env:NAME}}` or `{{env:NAME|fallback}}`.
Authentication request paths are static so tokens and environment secrets cannot enter request-event
telemetry; refresh credentials belong in declared headers or bodies.

```ts
const manifest = {
  schemaVersion: 1,
  id: "example",
  displayName: "Example",
  objective: "Test object and function authorization.",
  scope: {
    setupOperations: [{ method: "POST", path: "/login" }],
    protectedOperations: [
      {
        method: "GET",
        path: "/accounts/{id}",
        authorizedActors: [actorIds.userA, actorIds.userB, actorIds.administrator],
      },
      {
        method: "POST",
        path: "/admin/reindex",
        authorizedActors: [actorIds.administrator],
      },
    ],
  },
  identities: [
    { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" },
    {
      id: actorIds.userA,
      label: "User A",
      role: "user",
      authentication: {
        kind: "header-token",
        login: {
          request: {
            method: "POST",
            path: "/login",
            body: { email: { env: "EXAMPLE_USER_A" }, password: { env: "EXAMPLE_PASSWORD_A" } },
          },
          credential: { location: "body", pointer: "/accessToken" },
        },
      },
    },
  ],
} satisfies TargetManifest;

export const exampleProfile = createTargetProfile(manifest);
```

Exploration and validation targets instantiate these adapters independently. Validators therefore log
in afresh and never reuse exploration tokens, cookies, refresh state, or browser storage. A protected
operation declares intended access for authorization testing; it does not suppress requests from other
actors, because observing the target's own denial or bypass is the point of BOLA and privilege tests.

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
the remainder to exploration. The coordinator allocates that exploration pool across workers based
on current coverage and returns unused allocations when a worker retires. Validators share a fresh,
long-lived scoped target and authenticated session. Any exploration allowance left unused is
reclaimed for pending validation.

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
runtime requests, including methods and likely authentication, while following
scoped links. Discovery fills form controls from their types, labels, existing
values, and semantic hints, then submits only non-destructive search,
authentication, verification, or continuation workflows. It rescans each result
to follow multi-step flows instead of clicking every button on a page. File
inputs are described but never populated.

Supplied OpenAPI operations are merged with runtime evidence, including
summaries, templated paths, explicit request examples, and bounded values derived
from request schemas. Browser JSON, URL-encoded, and multipart bodies retain
their safe shape; multipart observations list field and filename metadata rather
than file content. GraphQL request documents are reduced to operation type,
name, and root fields. Primary-origin WebSocket URLs and frame counts/sizes are
observed while frames are forwarded unchanged; secondary-origin socket attempts
are recorded then closed. Active WebSocket testing is not performed.

Profiles can add exact loopback origins with `attackSurfaceOrigins`, classifying
each as `attackable` or `visit-only`. Attackable origins participate in form and
agent workflows. Visit-only origins permit passive document and asset reads,
but browser interactions, mutations, and agent requests are blocked.
Explorers may submit multiple findings and continue after each submission.
Findings carry severity, CWE, impact, mitigation, a safe impact-demonstration level, an ordered reproduction plan
containing exact REST methods, bodies, headers, and authentication mode, and one
structured proof predicate. Vulnerability-specific validators cover authorization
and data exposure, browser-visible XSS effects, HTTP OAST callbacks, verifier-only
canary retrieval, exact before/after state transitions, target-owned SQL semantic
differentials, and fresh computed command-execution challenges. Generic response
and timing differentials remain supporting evidence, and SSRF OAST callbacks do
not confirm command execution. BOLA proofs require different actor and resource-owner
identities plus concrete impact fields in a successful access response.

Impact levels are derived by code: `observation` for read-only HTTP evidence,
`bounded` for read-only browser/OAST collectors, and `state-change` for any
non-read-only request or policy-backed transition with a fresh-state reset hook.
A profile sets the maximum level, and `DELETE` is never accepted as a proof
demonstration. Explorer labels must exactly match the derived level.
Browser and OAST challenge issuance is itself unavailable below `bounded`, and
state reset hooks declare their exact request cost for validation preflight.

Exploit-chain submissions reference two to six already submitted findings in
execution order. Each adjacent link must select a scalar from the upstream
response and identify a named query, JSON-body, or header field in the downstream
request. Fresh validation replays steps in order, injects that fresh scalar into
the next request, and reconfirms every individual predicate before confirming
chain dataflow.

A shared campaign ledger coalesces duplicate concurrent requests, distinguishes
anonymous from authenticated observations, and exposes tested operations and
accepted findings to every worker. A persistent coordinator owns the live operation/access-mode
coverage model, testable hypotheses, per-worker request allocations, and validation queue. It claims
non-overlapping work, turns incoming status evidence into follow-up hypotheses, and receives a
structured debrief before each worker retires. High-confidence unfinished hypotheses are grouped by
specialty and handed to fresh specialist agents with focused budgets. Duplicate work therefore reuses
the first observation instead of consuming more request budget.

Quiver deduplicates findings by vulnerability category and normalized endpoint. Each accepted
finding enters independent validation immediately; validation is serialized against a separate
scoped target while the exploration fleet continues, then any budget-deferred replay is retried after
unused exploration capacity is reclaimed.
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
- Explicit exact-origin enforcement with redirects disabled; configured
  secondary origins are independently `attackable` or `visit-only`
- WebSockets are observed and forwarded unchanged, not actively tested
- Shared campaign budget with a reserved validation portion
- Browser proof documents and assets consume a policy-declared collector budget
- 12 KB cap for agent-visible responses
- No shell, browser, filesystem, or arbitrary network tools exposed directly to agents

The OAST listener binds to loopback by default. For a target in Docker, set
`QUIVER_OAST_BIND_HOST=0.0.0.0` and
`QUIVER_OAST_ADVERTISED_HOST=host.docker.internal` (with an appropriate
host-gateway mapping) so the target can reach the campaign-local listener.

## Evals

The live-model suite uses Flue through a `vitest-evals` harness. By default one
trial covers crAPI, VAmPI's vulnerable and secure modes, VulnerableApp, and the
randomized held-out fixture. Start the Docker-backed targets; the eval harness
starts an isolated held-out fixture for each matrix trial:

```sh
bun run target:up
bun run target:vampi:up
bun run target:vulnerableapp:up
bun run evals
```

Each campaign runs in an isolated process. The harness selects the target
profile from the shared registry; crAPI uses its read-only benchmark,
VulnerableApp automatically invokes its native DAST comparator, and the runner
automatically passes the two VAmPI confirmation sets through the differential
oracle. The held-out fixture is scored against its verifier-only canary policy.
Every profile records coverage, precision, validation completeness, duration,
model tokens, and failures in the same result envelope. VAmPI coverage is
operation coverage because its differential oracle classifies confirmations but
does not provide a recall denominator; the other profiles report benchmark or
fixture coverage, identified by `coverageKind`.

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

Run repeated full-matrix GLM trials and inspect the generated report with:

```sh
XBOW_EVAL_TRIALS=10 bun run evals:json
bun run evals:report
```

Each profile run uses a fresh process because Flue permits one runtime lifecycle
per process. Use `XBOW_EVAL_PROFILES=crapi,held-out` for a focused subset; VAmPI
subsets must include both `vampi-vulnerable` and `vampi-secure`. Per-profile target
overrides use names such as `XBOW_TARGET_CRAPI` and
`XBOW_TARGET_VAMPI_VULNERABLE`; the legacy `XBOW_TARGET` applies when exactly one
profile is selected. Quiver writes merged viewer input to
`.prototype/eval-results.json` and publishable aggregate metrics to
`.prototype/eval-summary.json` and `.prototype/eval-summary.md`: success rate,
per-profile and aggregate coverage, precision, validation completeness,
false-positive rate, requests per true positive, duration, token usage, failures,
and approximate model cost. Full failure messages remain in the per-trial JSON
artifacts; the aggregate, per-profile, and per-run summaries classify them as
model, infrastructure, budget, mapping, or validation failures and keep only a
concise error reason.

Trials are sequential by default. Set `XBOW_EVAL_CONCURRENCY=2` to use two
isolated worker processes when the local target and model provider can support
the extra load. Every held-out trial receives a distinct seed derived from a
random run seed. Set `XBOW_EVAL_SEED` to reproduce the same held-out fixtures;
the effective run seed and each held-out trial seed are recorded in the generated
output.

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
server also publishes the active seed atomically to `.prototype/held-out-seed`
so a separately started campaign can construct the hidden canary verifier. The
generated Markdown report includes severity, CWE, impact, mitigation, raw replay
responses, predicate checks, copyable requests, route coverage, model cost, and
an anchored chronological trace. Reports use schema version 8 and include
impact levels, collector artifacts, and exploit-chain outcomes.

## Developer loop

```sh
bun run test              # fast campaign, benchmark, mapper, CLI, and report tests
bun run test:integration  # live crawl and authentication checks against crAPI
bun run test:all          # fast and live HTTP suites
bun run evals             # isolated live GLM profile matrix (set XBOW_EVAL_TRIALS to repeat)
bun run verify            # formatting, linting, types, and fast tests
bun run security:secrets  # scan committable files for credentials (requires Docker)
```

## Security and disclosure

Keep API keys in the environment; local `.env*` files, private-key formats,
databases, logs, and generated campaign artifacts are excluded from Git. The
recommended `.prototype/` report location is intentionally ignored.

Campaign reports can still contain target application data even after
credential redaction. Inspect every report before sharing it, and never commit
output from a real assessment. Report vulnerabilities privately as described
in [SECURITY.md](SECURITY.md).
