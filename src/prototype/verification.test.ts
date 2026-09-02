import { describe, expect, it } from "vitest";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { Finding, ValidationObservation } from "./state.ts";
import { DefaultVerificationEngine, type VerificationEngine } from "./verification.ts";
import { vulnerableAppProfile } from "../targets/vulnerableapp.ts";
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

  it("confirms command injection with a fresh computed execution challenge", async () => {
    await using artifacts = new ProofArtifactStore();
    const verification: VerificationEngine = new DefaultVerificationEngine(
      vulnerableAppProfile,
      artifacts,
      { issueIntegerChallenge: () => 654_321 },
    );
    const commandFinding = commandInjectionFinding("LEVEL_1", "vulnerableapp-command-level-1");
    expect(verification.impactLevelFor(commandFinding.reproduction[0]!)).toBe("bounded");
    expect(
      verification.preflight(commandFinding, {
        observations: injectionObservations(commandFinding, [
          { content: `ping output\nQUIVER-COMMAND-${123_456 * 17 + 31}` },
        ]),
      }),
    ).toMatchObject({
      accepted: true,
      proof: {
        passed: true,
        predicate: "command-execution-challenge",
        classification: "command-execution",
      },
    });

    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:9090/VulnerableApp/"),
      requestBudget: 1,
      maximumImpactLevel: "bounded",
      transport: async (input) => {
        const command =
          new URL(input instanceof Request ? input.url : input).searchParams.get("ipaddress") ?? "";
        const challenge = Number(command.match(/17\*(\d+)\+31/)?.[1]);
        return Response.json({ content: `QUIVER-COMMAND-${challenge * 17 + 31}` });
      },
    });
    const replay = await verification.replay(commandFinding, target);
    expect(replay).toMatchObject({
      proof: { passed: true, predicate: "command-execution-challenge" },
      replayedFinding: {
        proof: { type: "command-execution-challenge", challenge: 654_321 },
      },
    });
    expect(replay.replayedFinding.reproduction[0]?.path).toContain("654321");
    expect(replay.replayedFinding.reproduction[0]?.path).not.toContain("123456");
  });

  it("rejects SSRF OAST evidence and the command allowlist secure control", async () => {
    await using artifacts = new ProofArtifactStore();
    const verification: VerificationEngine = new DefaultVerificationEngine(
      vulnerableAppProfile,
      artifacts,
    );
    const commandFinding = commandInjectionFinding("LEVEL_1", "vulnerableapp-command-level-1");
    const oastClaim: Finding = {
      ...commandFinding,
      proof: {
        type: "oast-callback",
        policyId: "vulnerableapp-command-level-1",
        probeId: "generic-oast",
        token: "callback-token",
        requestIndex: 0,
        callbackUrl: "http://127.0.0.1/callback-token",
        challenge: { location: "query", parameter: "ipaddress", template: "{{challenge}}" },
      },
    };
    const oastResult = verification.preflight(oastClaim, {
      observations: injectionObservations(oastClaim, [{ content: "callback sent" }]),
    });
    expect(oastResult.proof.classification).toBe("server-side-request-forgery");
    expect(oastResult.proof.checks[0]).toMatchObject({
      passed: false,
      description: expect.stringContaining("compatible with"),
    });

    const secureFinding = commandInjectionFinding(
      "LEVEL_6",
      "vulnerableapp-command-level-6-secure-control",
    );
    expect(
      verification.preflight(secureFinding, {
        observations: injectionObservations(secureFinding, [{ content: "" }]),
      }).accepted,
    ).toBe(false);
  });
});

function injectionFinding(
  overrides: Pick<Finding, "category" | "endpoint" | "reproduction" | "proof"> & Partial<Finding>,
): Finding {
  return {
    fingerprint: `${overrides.category}:GET:${overrides.endpoint}`,
    agentId: "explorer-1",
    title: "Injection proof",
    severity: "high",
    cwe: overrides.category === "sql-injection" ? "CWE-89" : "CWE-78",
    method: "GET",
    resource: "target-owned fixture",
    rationale: "The target-owned injection verifier passed.",
    impact: "Backend interpreter execution was confirmed.",
    mitigation: "Use parameterized APIs and avoid shell evaluation.",
    impactLevel: overrides.category === "command-injection" ? "bounded" : "observation",
    ...overrides,
  };
}

function commandInjectionFinding(level: string, policyId: string): Finding {
  const challenge = 123_456;
  const command = `127.0.0.1;printf QUIVER-COMMAND-%s $((17*${challenge}+31))`;
  const endpoint = `/VulnerableApp/CommandInjection/${level}`;
  return injectionFinding({
    category: "command-injection",
    endpoint,
    reproduction: [
      {
        path: `${endpoint}?ipaddress=${encodeURIComponent(command)}`,
        actorId: "anonymous",
      },
    ],
    proof: {
      type: "command-execution-challenge",
      policyId,
      requestIndex: 0,
      challenge,
    },
  });
}

function injectionObservations(
  finding: Finding,
  bodies: readonly unknown[],
): ValidationObservation[] {
  return finding.reproduction.map((request, index) => ({
    method: request.method ?? "GET",
    status: 200,
    path: request.path,
    actorId: request.actorId,
    body: bodies[index],
    truncated: false,
  }));
}
