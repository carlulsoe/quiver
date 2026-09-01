import { actorIds } from "../prototype/sessions.ts";
import { createTargetProfile } from "../prototype/target-profile.ts";
import type { TargetManifest } from "../prototype/target-manifest.ts";

export const vulnerableAppManifest = {
  schemaVersion: 1,
  id: "vulnerableapp",
  displayName: "OWASP VulnerableApp",
  objective:
    "Find machine-provable read-only vulnerabilities for comparison with VulnerableApp's native DAST ground truth. Prefer specific endpoints and CWE identifiers so detections and unmatched claims can be scored objectively. For command injection, use only a declared target-owned arithmetic challenge; never run arbitrary commands.",
  scope: {
    maximumImpactLevel: "bounded",
    deniedOperations: [
      { method: "GET", path: "/VulnerableApp/h2" },
      { method: "POST", path: "/VulnerableApp/scanner/benchmark" },
    ],
  },
  identities: [{ id: actorIds.anonymous, label: "Anonymous", role: "anonymous" }],
} satisfies TargetManifest;

export const vulnerableAppProfile = createTargetProfile(vulnerableAppManifest, {
  proofPolicies: [
    {
      id: "vulnerableapp-blind-sql-level-1",
      kind: "sql-semantic-differential",
      category: "sql-injection",
      description:
        "A false and true predicate against the vulnerable numeric car lookup must change isCarPresent.",
      endpoint: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_1",
      method: "GET",
      mutation: {
        location: "query",
        parameter: "id",
        controlValue: "100 AND 2=1",
        probeValue: "100 OR 2=2",
      },
      response: { jsonPointer: "/isCarPresent", controlValue: false, probeValue: true },
    },
    {
      id: "vulnerableapp-blind-sql-level-3-secure-control",
      kind: "sql-semantic-differential",
      category: "sql-injection",
      description:
        "The prepared-statement car lookup is a secure control for the same semantic pair.",
      endpoint: "/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_3",
      method: "GET",
      mutation: {
        location: "query",
        parameter: "id",
        controlValue: "100 AND 2=1",
        probeValue: "100 OR 2=2",
      },
      response: { jsonPointer: "/isCarPresent", controlValue: false, probeValue: true },
    },
    {
      id: "vulnerableapp-command-level-1",
      kind: "command-execution-challenge",
      category: "command-injection",
      description:
        "The vulnerable ping utility must compute a fresh arithmetic marker through the shell.",
      endpoint: "/VulnerableApp/CommandInjection/LEVEL_1",
      method: "GET",
      challenge: {
        location: "query",
        parameter: "ipaddress",
        template: "127.0.0.1;printf QUIVER-COMMAND-%s $((17*{{challenge}}+31))",
      },
      outputJsonPointer: "/content",
      outputPrefix: "QUIVER-COMMAND-",
      multiplier: 17,
      addend: 31,
      challengeMinimum: 100_000,
      challengeMaximum: 999_999,
    },
    {
      id: "vulnerableapp-command-level-6-secure-control",
      kind: "command-execution-challenge",
      category: "command-injection",
      description: "The IP allowlist is a secure control for the same shell challenge.",
      endpoint: "/VulnerableApp/CommandInjection/LEVEL_6",
      method: "GET",
      challenge: {
        location: "query",
        parameter: "ipaddress",
        template: "127.0.0.1;printf QUIVER-COMMAND-%s $((17*{{challenge}}+31))",
      },
      outputJsonPointer: "/content",
      outputPrefix: "QUIVER-COMMAND-",
      multiplier: 17,
      addend: 31,
      challengeMinimum: 100_000,
      challengeMaximum: 999_999,
    },
  ],
});
