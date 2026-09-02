import type { Finding, ValidationObservation } from "./state.ts";

export function injectionFinding(
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

export function commandInjectionFinding(level: string, policyId: string): Finding {
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

export function injectionObservations(
  finding: Finding,
  bodies: readonly ValidationObservation["body"][],
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
