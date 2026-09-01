import { describe, expect, it, vi } from "vitest";
import { ScopedTarget } from "../prototype/scoped-target.ts";
import { brokenCrystalsProfile } from "./broken-crystals.ts";
import { vampiVulnerableProfile } from "./vampi.ts";
import { vulnerableAppProfile } from "./vulnerableapp.ts";

describe("additional target profiles", () => {
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

  it("binds VulnerableApp injection proofs to vulnerable and secure-control levels", () => {
    expect(vulnerableAppProfile.maximumImpactLevel).toBe("bounded");
    expect(
      vulnerableAppProfile.proofPolicies?.map((policy) => ({
        id: policy.id,
        kind: policy.kind,
        endpoint: "endpoint" in policy ? policy.endpoint : undefined,
      })),
    ).toEqual([
      {
        id: "vulnerableapp-blind-sql-level-1",
        kind: "sql-semantic-differential",
        endpoint: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1",
      },
      {
        id: "vulnerableapp-blind-sql-level-3-secure-control",
        kind: "sql-semantic-differential",
        endpoint: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_3",
      },
      {
        id: "vulnerableapp-command-level-1",
        kind: "command-execution-challenge",
        endpoint: "/VulnerableApp/CommandInjection/LEVEL_1",
      },
      {
        id: "vulnerableapp-command-level-6-secure-control",
        kind: "command-execution-challenge",
        endpoint: "/VulnerableApp/CommandInjection/LEVEL_6",
      },
    ]);
  });
});
