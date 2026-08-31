export interface HeldOutFixture {
  seed: string;
  namespace: string;
  actorId: string;
  foreignOwnerId: string;
  ownedVaultId: string;
  foreignVaultId: string;
  canary: string;
  fetch(request: Request): Promise<Response>;
}

const authorization = "Bearer quiver-showcase-user";

export function createHeldOutFixture(seed: string): HeldOutFixture {
  if (!seed.trim()) throw new Error("Held-out seed must not be empty");
  const namespace = `n-${token(seed, "namespace")}`;
  const asset = `bundle-${token(seed, "asset")}.js`;
  const actorId = uuid(seed, "actor");
  const foreignOwnerId = uuid(seed, "owner");
  const ownedVaultId = uuid(seed, "owned-vault");
  const foreignVaultId = uuid(seed, "foreign-vault");
  const canary = `QUIVER-CANARY-${token(seed, "canary").toUpperCase()}`;
  const api = `/api/${namespace}`;

  return {
    seed,
    namespace,
    actorId,
    foreignOwnerId,
    ownedVaultId,
    foreignVaultId,
    canary,
    async fetch(request) {
      const url = new URL(request.url);
      if (request.method !== "GET") return json({ error: "method-not-allowed" }, 405);
      if (url.pathname === "/") {
        return new Response(
          `<!doctype html><html><head><title>Ledgerly</title></head><body><main>Ledgerly workspace</main><script src="/assets/${asset}"></script></body></html>`,
          { headers: { "content-type": "text/html" } },
        );
      }
      if (url.pathname === `/assets/${asset}`) {
        return new Response(
          [
            `fetch("${api}/session",{method:"GET",headers:{Authorization:"Bearer "+token}});`,
            `fetch("${api}/vaults",{method:"GET",headers:{Authorization:"Bearer "+token}});`,
            `fetch("${api}/directory",{method:"GET",headers:{Authorization:"Bearer "+token}});`,
            `fetch(\`${api}/vaults/\${vaultId}\`,{method:"GET",headers:{Authorization:"Bearer "+token}});`,
            `fetch(\`${api}/profiles/\${principalId}\`,{method:"GET",headers:{Authorization:"Bearer "+token}});`,
          ].join("\n"),
          { headers: { "content-type": "application/javascript" } },
        );
      }
      if (!isAuthorized(request)) return json({ error: "unauthorized" }, 401);
      if (url.pathname === `${api}/session`) {
        return json({ principal: { id: actorId, email: "showcase-user@ledgerly.test" } });
      }
      if (url.pathname === `${api}/vaults`) {
        return json({ vaults: [{ id: ownedVaultId, ownerId: actorId, label: "My records" }] });
      }
      if (url.pathname === `${api}/directory`) {
        return json({
          colleagues: [
            {
              principalId: foreignOwnerId,
              displayName: "Held Out Colleague",
              featuredVaultId: foreignVaultId,
            },
          ],
        });
      }
      if (url.pathname === `${api}/vaults/${ownedVaultId}`) {
        return json({
          id: ownedVaultId,
          owner: { id: actorId, email: "showcase-user@ledgerly.test" },
          record: { summary: "Owned control record" },
        });
      }
      if (url.pathname === `${api}/vaults/${foreignVaultId}`) {
        return json({
          id: foreignVaultId,
          owner: { id: foreignOwnerId, email: "held-out-owner@ledgerly.test" },
          record: { summary: "Cross-principal payroll record", canary },
        });
      }
      if (url.pathname.startsWith(`${api}/profiles/`)) {
        const requestedPrincipal = url.pathname.slice(`${api}/profiles/`.length);
        return requestedPrincipal === actorId
          ? json({ id: actorId, email: "showcase-user@ledgerly.test" })
          : json({ error: "forbidden" }, 403);
      }
      return json({ error: "not-found" }, 404);
    },
  };
}

function isAuthorized(request: Request): boolean {
  return request.headers.get("authorization") === authorization;
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "cache-control": "no-store" } });
}

function token(seed: string, purpose: string): string {
  return hash(`${purpose}:${seed}`).toString(36).padStart(7, "0").slice(0, 7);
}

function uuid(seed: string, purpose: string): string {
  const parts = Array.from({ length: 4 }, (_, index) =>
    hash(`${purpose}:${index}:${seed}`).toString(16).padStart(8, "0"),
  ).join("");
  return `${parts.slice(0, 8)}-${parts.slice(8, 12)}-4${parts.slice(13, 16)}-a${parts.slice(17, 20)}-${parts.slice(20, 32)}`;
}

function hash(value: string): number {
  let result = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    result ^= value.charCodeAt(index);
    result = Math.imul(result, 0x01000193);
  }
  return result >>> 0;
}
