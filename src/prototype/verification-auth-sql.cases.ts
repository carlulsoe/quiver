import { describe, expect, it } from "vitest";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { Finding } from "./state.ts";
import { DefaultVerificationEngine, type VerificationEngine } from "./verification.ts";
import { vulnerableAppProfile } from "../targets/vulnerableapp.ts";
import { injectionFinding, injectionObservations } from "./verification-test-helpers.ts";

const finding: Finding = {
  fingerprint: "security-misconfiguration:GET:/health",
  agentId: "explorer-1",
  title: "Public build details",
  category: "security-misconfiguration",
  severity: "low",
  cwe: "CWE-200",
  endpoint: "/health",
  method: "GET",
  resource: "build metadata",
  rationale: "Internal build metadata is public.",
  impact: "Deployment details are disclosed.",
  mitigation: "Return only health status.",
  impactLevel: "observation",
  reproduction: [{ path: "/health", actorId: "anonymous" }],
  proof: {
    type: "unauthenticated-success",
    requestIndex: 0,
    evidencePointers: ["/build"],
  },
};

describe("verification authentication and SQL", () => {
  it("coalesces concurrent first-use authentication on one validation target", async () => {
    await using artifacts = new ProofArtifactStore();
    let authenticationCount = 0;
    let releaseAuthentication!: () => void;
    let authenticationStarted!: () => void;
    const authenticationGate = new Promise<void>((resolve) => {
      releaseAuthentication = resolve;
    });
    const started = new Promise<void>((resolve) => {
      authenticationStarted = resolve;
    });
    const verification = new DefaultVerificationEngine(
      {
        id: "concurrent-authentication",
        displayName: "Concurrent authentication",
        objective: "Coalesce validation login.",
        actorIds: [actorIds.userA],
        authenticate: async (target, requestedActorIds) => {
          authenticationCount += 1;
          authenticationStarted();
          await authenticationGate;
          for (const actorId of requestedActorIds ?? [actorIds.userA]) {
            target.setSession(actorId, { headers: { authorization: "Bearer validation" } });
          }
          return { authContext: "validation-user-a" };
        },
      },
      artifacts,
    );
    const authenticatedFinding: Finding = {
      ...finding,
      fingerprint: "security-misconfiguration:GET:/authenticated-health",
      reproduction: [{ path: "/authenticated-health", actorId: actorIds.userA }],
    };
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      transport: async () => Response.json({ build: "internal-42" }),
    });

    const firstReplay = verification.replay(authenticatedFinding, target);
    const secondReplay = verification.replay(authenticatedFinding, target);
    await started;
    expect(authenticationCount).toBe(1);
    releaseAuthentication();

    await expect(Promise.all([firstReplay, secondReplay])).resolves.toHaveLength(2);
    expect(authenticationCount).toBe(1);
    expect(target.requestsUsed).toBe(2);
  });

  it("confirms a target-owned SQL semantic differential", async () => {
    await using artifacts = new ProofArtifactStore();
    const verification: VerificationEngine = new DefaultVerificationEngine(
      vulnerableAppProfile,
      artifacts,
    );
    const sqlFinding = injectionFinding({
      category: "sql-injection",
      endpoint: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1",
      reproduction: [
        {
          path: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1?id=100+AND+2%3D1",
          actorId: "anonymous",
        },
        {
          path: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1?id=100+OR+2%3D2",
          actorId: "anonymous",
        },
      ],
      proof: {
        type: "sql-semantic-differential",
        policyId: "vulnerableapp-blind-sql-level-1",
        controlRequestIndex: 0,
        probeRequestIndex: 1,
      },
    });

    expect(
      verification.preflight(sqlFinding, {
        observations: injectionObservations(sqlFinding, [
          { isCarPresent: false },
          { isCarPresent: true },
        ]),
      }),
    ).toMatchObject({
      accepted: true,
      proof: { passed: true, predicate: "sql-semantic-differential" },
    });
  });

  it("rejects a coincidental SQL difference and the prepared-statement secure control", async () => {
    await using artifacts = new ProofArtifactStore();
    const verification: VerificationEngine = new DefaultVerificationEngine(
      vulnerableAppProfile,
      artifacts,
    );
    const vulnerableFinding = injectionFinding({
      category: "sql-injection",
      endpoint: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1",
      reproduction: [
        {
          path: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1?id=ordinary",
          actorId: "anonymous",
        },
        {
          path: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1?id=other",
          actorId: "anonymous",
        },
      ],
      proof: {
        type: "sql-semantic-differential",
        policyId: "vulnerableapp-blind-sql-level-1",
        controlRequestIndex: 0,
        probeRequestIndex: 1,
      },
    });
    expect(
      verification.preflight(vulnerableFinding, {
        observations: injectionObservations(vulnerableFinding, [
          { isCarPresent: false },
          { isCarPresent: true },
        ]),
      }).accepted,
    ).toBe(false);

    const secureFinding = injectionFinding({
      ...vulnerableFinding,
      endpoint: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_3",
      reproduction: [
        {
          path: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_3?id=100+AND+2%3D1",
          actorId: "anonymous",
        },
        {
          path: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_3?id=100+OR+2%3D2",
          actorId: "anonymous",
        },
      ],
      proof: {
        type: "sql-semantic-differential",
        policyId: "vulnerableapp-blind-sql-level-3-secure-control",
        controlRequestIndex: 0,
        probeRequestIndex: 1,
      },
    });
    expect(
      verification.preflight(secureFinding, {
        observations: injectionObservations(secureFinding, [
          { isCarPresent: false },
          { isCarPresent: false },
        ]),
      }).accepted,
    ).toBe(false);
  });
});
