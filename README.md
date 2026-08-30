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

The model defaults to `openrouter/z-ai/glm-5.3-flash`. Because Flue 2.0.3's
bundled OpenRouter catalog predates that model, the prototype registers its
current OpenRouter metadata explicitly. Override it with `XBOW_MODEL` using any
Flue model specifier.

## Run the prototype

This requires Bun, Docker Compose, and an `OPENROUTER_API_KEY` in the
environment.

Start the pinned OWASP crAPI 1.1.5 checkout on loopback port 8888, then run:

```sh
bun run target:up
bun run prototype -- http://127.0.0.1:8888
```

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

## Observed verdict

On 2026-08-30, Flue 2.0.3 completed real model and tool turns inside Bun 1.4.0
using `openrouter/z-ai/glm-5.3-flash`. Two short-lived explorers independently
tested the local target. A fresh validator confirmed one vehicle-location BOLA
with deterministic cross-owner and coordinate checks. The successful run used
16 of the 30 permitted HTTP requests.
