import { describe, expect, it } from "vitest";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";
import { DefaultVerificationEngine, type VerificationEngine } from "./verification.ts";

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

describe("verification engine", () => {
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
});
