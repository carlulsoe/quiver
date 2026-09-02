import { describe, expect, it } from "vitest";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { Finding, ValidationObservation } from "./state.ts";
import { DefaultVerificationEngine, type VerificationEngine } from "./verification.ts";
import { createTargetProfile } from "./target-profile.ts";

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

describe("verification replay", () => {
  it("owns both exploration acceptance and independent replay", async () => {
    await using artifacts = new ProofArtifactStore();
    const verification: VerificationEngine = new DefaultVerificationEngine(
      {
        id: "verification-test",
        displayName: "Verification test",
        objective: "Exercise the verification seam.",
        maximumImpactLevel: "observation",
      },
      artifacts,
    );
    const observations = [
      {
        method: "GET" as const,
        status: 200,
        path: "/health",
        actorId: "anonymous",
        body: { build: "internal-42" },
        truncated: false,
      },
    ];

    expect(verification.preflight(finding, { observations })).toMatchObject({
      accepted: true,
      proof: { passed: true, predicate: "unauthenticated-success" },
    });

    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      maximumImpactLevel: "observation",
      transport: async () => Response.json({ build: "internal-42" }),
    });
    await expect(verification.replay(finding, target)).resolves.toMatchObject({
      fingerprint: finding.fingerprint,
      proof: { passed: true, predicate: "unauthenticated-success" },
      observations: [{ actorId: "anonymous", body: { build: "internal-42" } }],
    });
  });

  it("carries manifest access policy into authentication-bypass preflight and replay", async () => {
    await using artifacts = new ProofArtifactStore();
    const profile = createTargetProfile({
      schemaVersion: 1,
      id: "authentication-bypass-proof",
      displayName: "Authentication bypass proof",
      objective: "Prove anonymous access to a protected operation.",
      scope: {
        protectedOperations: [
          { method: "GET", path: "/account", authorizedActors: [actorIds.userA] },
        ],
        maximumImpactLevel: "observation",
      },
      identities: [
        { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" },
        {
          id: actorIds.userA,
          label: "User A",
          role: "user",
          authentication: {
            kind: "header-token",
            credential: { location: "literal", value: "user-a-token" },
          },
        },
      ],
    });
    const verification = new DefaultVerificationEngine(profile, artifacts);
    const bypass: Finding = {
      ...finding,
      fingerprint: "authentication-bypass:GET:/account",
      category: "authentication-bypass",
      endpoint: "/account",
      reproduction: [
        { path: "/account", actorId: actorIds.userA },
        { path: "/account", actorId: actorIds.anonymous },
      ],
      proof: {
        type: "authentication-bypass",
        authenticatedRequestIndex: 0,
        anonymousRequestIndex: 1,
        evidencePointers: ["/account/id"],
      },
    };
    const observations: ValidationObservation[] = bypass.reproduction.map((request) => ({
      method: "GET",
      status: 200,
      path: request.path,
      actorId: request.actorId,
      body: { account: { id: "account-7" } },
      truncated: false,
    }));

    expect(verification.preflight(bypass, { observations })).toMatchObject({
      accepted: true,
      proof: { predicate: "authentication-bypass", passed: true },
    });

    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      maximumImpactLevel: "observation",
      transport: async () => Response.json({ account: { id: "account-7" } }),
    });
    await expect(verification.replay(bypass, target)).resolves.toMatchObject({
      proof: { predicate: "authentication-bypass", passed: true },
      observations: [{ actorId: actorIds.userA }, { actorId: actorIds.anonymous }],
    });
  });
});
