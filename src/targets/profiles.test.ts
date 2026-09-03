import { describe, expect, it, vi } from "vitest";
import { ScopedTarget } from "../prototype/scoped-target.ts";
import { brokenCrystalsProfile } from "./broken-crystals.ts";
import { crapiProfile } from "./crapi.ts";
import { heldOutProfile } from "./held-out.ts";
import { vampiVulnerableProfile } from "./vampi.ts";
import { vulnerableAppProfile } from "./vulnerableapp.ts";

describe("additional target profiles", () => {
  it("exposes bundled TypeScript profiles as thin declarative adapters", () => {
    expect(brokenCrystalsProfile.manifest?.id).toBe(brokenCrystalsProfile.id);
    expect(vampiVulnerableProfile.manifest?.id).toBe(vampiVulnerableProfile.id);
    expect(brokenCrystalsProfile.callbackConfigurationFingerprint).toBe("manifest-derived:1");
    expect(heldOutProfile.callbackConfigurationFingerprint).toBeTruthy();
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

  it("blocks router-equivalent crAPI mechanic-report routes but allows neighbors", async () => {
    const requested: string[] = [];
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 3,
      deniedRequests: crapiProfile.deniedRequests,
      transport: async (input) => {
        requested.push(new URL(String(input)).pathname);
        return Response.json({ ok: true });
      },
    });
    const denied = [
      "/workshop/api/mechanic/receive_report",
      "/workshop/api/mechanic/receive_report/",
      "/workshop/api/%6dechanic/receive%5freport",
      "/workshop/api/mechanic/mechanic_report?format=json",
      "/workshop/api/mechanic/mechanic%5freport/",
    ];

    for (const path of denied) {
      await expect(target.request({ path })).rejects.toThrow("denied by the target profile");
    }
    await expect(
      target.request({ path: "/workshop/api/mechanic/receive_reports" }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      target.request({ path: "/workshop/api/mechanics/mechanic_report" }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      target.request({ path: "/identity/api/v2/user/dashboard" }),
    ).resolves.toMatchObject({ status: 200 });
    expect(requested).toEqual([
      "/workshop/api/mechanic/receive_reports",
      "/workshop/api/mechanics/mechanic_report",
      "/identity/api/v2/user/dashboard",
    ]);
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
