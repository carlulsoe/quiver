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

const authorizations = {
  "Bearer quiver-showcase-user": "user-a",
  "Bearer quiver-showcase-user-b": "user-b",
  "Bearer quiver-showcase-admin": "administrator",
} as const;

export function createHeldOutFixture(seed: string): HeldOutFixture {
  if (!seed.trim()) throw new Error("Held-out seed must not be empty");
  const namespace = `n-${token(seed, "namespace")}`;
  const asset = `bundle-${token(seed, "asset")}.js`;
  const actorId = uuid(seed, "actor");
  const foreignOwnerId = uuid(seed, "owner");
  const administratorId = uuid(seed, "administrator");
  const ownedVaultId = uuid(seed, "owned-vault");
  const foreignVaultId = uuid(seed, "foreign-vault");
  const canary = heldOutCanary(seed);
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
      if (request.method === "GET" && url.pathname === "/") {
        return new Response(
          `<!doctype html><html><head><title>Ledgerly</title></head><body><main>Ledgerly workspace</main><button id="audit">Load audit</button><script src="/assets/${asset}"></script></body></html>`,
          { headers: { "content-type": "text/html" } },
        );
      }
      if (request.method === "GET" && url.pathname === `/assets/${asset}`) {
        return new Response(
          [
            `const token="quiver-showcase-user";`,
            `fetch("${api}/session",{method:"GET",headers:{Authorization:"Bearer "+token}});`,
            `fetch("${api}/vaults",{headers:{Authorization:"Bearer "+token}}).then(response=>response.json()).then(data=>fetch(\`${api}/vaults/\${data.vaults[0].id}\`,{headers:{Authorization:"Bearer "+token}}));`,
            `fetch("${api}/directory",{headers:{Authorization:"Bearer "+token}}).then(response=>response.json()).then(data=>{const colleague=data.colleagues[0];fetch(\`${api}/vaults/\${colleague.featuredVaultId}\`,{headers:{Authorization:"Bearer "+token}});fetch(\`${api}/profiles/\${colleague.principalId}\`,{headers:{Authorization:"Bearer "+token}})});`,
            `document.querySelector("#audit").addEventListener("click",()=>fetch("${api}/audit",{method:"POST",headers:{"content-type":"application/json",Authorization:"Bearer "+token},body:"{}"}));`,
          ].join("\n"),
          { headers: { "content-type": "application/javascript" } },
        );
      }
      const principal = authenticate(request);
      if (!principal) return json({ error: "unauthorized" }, 401);
      if (url.pathname === `${api}/audit`) {
        if (request.method !== "POST") return json({ error: "method-not-allowed" }, 405);
        return principal === "administrator"
          ? json({ accepted: true })
          : json({ error: "forbidden" }, 403);
      }
      if (request.method !== "GET") return json({ error: "method-not-allowed" }, 405);
      const principalId =
        principal === "user-a"
          ? actorId
          : principal === "user-b"
            ? foreignOwnerId
            : administratorId;
      if (url.pathname === `${api}/session`) {
        return json({ principal: { id: principalId, role: principal } });
      }
      if (url.pathname === `${api}/vaults`) {
        const vaults =
          principal === "user-b"
            ? [{ id: foreignVaultId, ownerId: foreignOwnerId, label: "My records" }]
            : [{ id: ownedVaultId, ownerId: actorId, label: "My records" }];
        return json({ vaults });
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
        return requestedPrincipal === principalId || principal === "administrator"
          ? json({ id: requestedPrincipal, role: principal })
          : json({ error: "forbidden" }, 403);
      }
      return json({ error: "not-found" }, 404);
    },
  };
}

export function heldOutCanary(seed: string): string {
  return `QUIVER-CANARY-${token(seed, "canary").toUpperCase()}`;
}

function authenticate(
  request: Request,
): (typeof authorizations)[keyof typeof authorizations] | undefined {
  const authorization = request.headers.get("authorization");
  return authorization ? authorizations[authorization as keyof typeof authorizations] : undefined;
}

function json<T>(body: T, status = 200): Response {
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
