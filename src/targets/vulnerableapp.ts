import { actorIds } from "../prototype/sessions.ts";
import { createTargetProfile } from "../prototype/target-profile.ts";
import type { TargetManifest } from "../prototype/target-manifest.ts";

export const vulnerableAppManifest = {
  schemaVersion: 1,
  id: "vulnerableapp",
  displayName: "OWASP VulnerableApp",
  objective:
    "Find machine-provable read-only vulnerabilities for comparison with VulnerableApp's native DAST ground truth. Prefer specific endpoints and CWE identifiers so detections and unmatched claims can be scored objectively.",
  scope: {
    deniedOperations: [
      { method: "GET", path: "/VulnerableApp/h2" },
      { method: "POST", path: "/VulnerableApp/scanner/benchmark" },
    ],
  },
  identities: [{ id: actorIds.anonymous, label: "Anonymous", role: "anonymous" }],
} satisfies TargetManifest;

export const vulnerableAppProfile = createTargetProfile(vulnerableAppManifest);
