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

  it("publishes only live randomized route intelligence to the crawler", async () => {
    const fixture = createHeldOutFixture("crawl-seed");
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8899"),
      requestBudget: 2,
      transport: (input, init) => fixture.fetch(new Request(input, init)),
    });

    const map = await target.crawl();

    expect(map.routeDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: `/api/${fixture.namespace}/session` }),
        expect.objectContaining({ path: `/api/${fixture.namespace}/vaults/{vaultId}` }),
      ]),
    );
    expect(JSON.stringify(map)).not.toContain(fixture.canary);
  });
});
