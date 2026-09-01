import { describe, expect, it, vi } from "vitest";
import { ScopedTarget } from "../prototype/scoped-target.ts";
import { brokenCrystalsProfile } from "./broken-crystals.ts";
import { heldOutProfile } from "./held-out.ts";
import { vampiVulnerableProfile } from "./vampi.ts";

describe("additional target profiles", () => {
  it("exposes bundled TypeScript profiles as thin declarative adapters", () => {
    expect(brokenCrystalsProfile.manifest?.id).toBe(brokenCrystalsProfile.id);
    expect(vampiVulnerableProfile.manifest?.id).toBe(vampiVulnerableProfile.id);
    expect(heldOutProfile.actorIds).toEqual(["ordinary-user", "second-user", "privileged-user"]);
    expect(heldOutProfile.protectedOperations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          method: "POST",
          authorizedActors: ["privileged-user"],
        }),
      ]),
    );
  });

  it("captures Broken Crystals' response-header token for authenticated requests", async () => {
    const transport = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      if (init?.method === "POST") {
        return Response.json(
          { email: "user" },
          { status: 201, headers: { authorization: "fixture-jwt" } },
        );
      }
      return Response.json({ ok: true });
    });
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:3000"),
      requestBudget: 3,
      allowedRequests: brokenCrystalsProfile.allowedRequests,
      transport,
    });

    await expect(brokenCrystalsProfile.authenticate!(target)).resolves.toEqual({
      authContext: "ordinary-test-user",
    });
    await target.request({ path: "/api/users/me", actorId: "ordinary-user" });
    expect(transport.mock.calls[1]![1]).toMatchObject({
      headers: { authorization: "fixture-jwt" },
    });
  });

  it("logs into VAmPI without resetting the initialized regression fixture", async () => {
    const transport = vi.fn(async () => Response.json({ auth_token: "vampi-jwt" }));
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:5002/ui/"),
      requestBudget: 3,
      allowedRequests: vampiVulnerableProfile.allowedRequests,
      deniedRequests: vampiVulnerableProfile.deniedRequests,
      transport,
    });

    await expect(vampiVulnerableProfile.authenticate!(target)).resolves.toEqual({
      authContext: "name1",
    });
    expect(transport).toHaveBeenCalledTimes(1);
    await expect(target.request({ path: "/createdb" })).rejects.toThrow(
      "denied by the target profile",
    );
  });
});
