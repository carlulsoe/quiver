import { describe, expect, it } from "vitest";
import { ScopedTarget } from "../prototype/scoped-target.ts";
import { createHeldOutFixture } from "./held-out-fixture.ts";

describe("randomized held-out target", () => {
  it("randomizes routes, identifiers, and canaries by seed", () => {
    const first = createHeldOutFixture("alpha");
    const same = createHeldOutFixture("alpha");
    const second = createHeldOutFixture("beta");

    expect(same).toMatchObject({
      namespace: first.namespace,
      actorId: first.actorId,
      foreignVaultId: first.foreignVaultId,
      canary: first.canary,
    });
    expect(second.namespace).not.toBe(first.namespace);
    expect(second.foreignVaultId).not.toBe(first.foreignVaultId);
    expect(second.canary).not.toBe(first.canary);
  });

  it("exposes a canary-backed cross-principal record while enforcing a profile control", async () => {
    const fixture = createHeldOutFixture("integration-seed");
    const base = `http://127.0.0.1:8899/api/${fixture.namespace}`;
    const headers = { authorization: "Bearer quiver-showcase-user" };

    const foreign = await fixture
      .fetch(new Request(`${base}/vaults/${fixture.foreignVaultId}`, { headers }))
      .then((response) => response.json());
    const protectedProfile = await fixture.fetch(
      new Request(`${base}/profiles/${fixture.foreignOwnerId}`, { headers }),
    );

    expect(foreign).toMatchObject({
      owner: { id: fixture.foreignOwnerId },
      record: { canary: fixture.canary },
    });
    expect(protectedProfile.status).toBe(403);
  });

  it("distinguishes user A, user B, and administrator authorization", async () => {
    const fixture = createHeldOutFixture("principal-seed");
    const base = `http://127.0.0.1:8899/api/${fixture.namespace}`;
    const userB = { authorization: "Bearer quiver-showcase-user-b" };
    const administrator = { authorization: "Bearer quiver-showcase-admin" };

    const userBProfile = await fixture.fetch(
      new Request(`${base}/profiles/${fixture.foreignOwnerId}`, { headers: userB }),
    );
    const administratorProfile = await fixture.fetch(
      new Request(`${base}/profiles/${fixture.foreignOwnerId}`, { headers: administrator }),
    );
    const userBAudit = await fixture.fetch(
      new Request(`${base}/audit`, { method: "POST", headers: userB }),
    );
    const administratorAudit = await fixture.fetch(
      new Request(`${base}/audit`, { method: "POST", headers: administrator }),
    );

    expect(userBProfile.status).toBe(200);
    expect(administratorProfile.status).toBe(200);
    expect(userBAudit.status).toBe(403);
    expect(administratorAudit.status).toBe(200);
  });

  it("publishes only live randomized route intelligence to the mapper", async () => {
    const fixture = createHeldOutFixture("crawl-seed");
    const server = Bun.serve({ port: 0, fetch: fixture.fetch });
    try {
      const requested: string[] = [];
      const target = new ScopedTarget({
        target: new URL(`http://127.0.0.1:${server.port}`),
        requestBudget: 10,
        timeoutMs: 10_000,
        onRequest: ({ method, path }) => requested.push(`${method} ${path}`),
        openApi: {
          openapi: "3.1.0",
          paths: {
            [`/api/${fixture.namespace}/audit`]: {
              post: { summary: "Load the audit trail" },
            },
            [`/api/${fixture.namespace}/vaults/{vaultId}`]: {
              patch: { summary: "Update a vault record" },
            },
          },
        },
      });

      const map = await target.mapAttackSurface();

      expect(map.routeDetails).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ path: `/api/${fixture.namespace}/session` }),
          expect.objectContaining({ path: `/api/${fixture.namespace}/vaults` }),
          expect.objectContaining({
            path: `/api/${fixture.namespace}/audit`,
            methods: ["POST"],
            callSites: [expect.objectContaining({ method: "POST" })],
          }),
          expect.objectContaining({
            path: `/api/${fixture.namespace}/vaults/{vaultId}`,
            methods: ["PATCH"],
            summary: "Update a vault record",
          }),
          expect.objectContaining({
            path: `/api/${fixture.namespace}/vaults/{id}`,
            examples: expect.arrayContaining([
              `/api/${fixture.namespace}/vaults/${fixture.foreignVaultId}`,
            ]),
          }),
        ]),
      );
      expect(JSON.stringify(map)).not.toContain(fixture.canary);
      expect(requested.some((request) => request.includes("/assets/"))).toBe(true);
      expect(requested).not.toContain(`POST /api/${fixture.namespace}/audit`);
    } finally {
      server.stop(true);
    }
  }, 40_000);
});
