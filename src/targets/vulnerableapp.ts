import type { TargetProfile } from "../prototype/target-profile.ts";

export const vulnerableAppProfile: TargetProfile = {
  id: "vulnerableapp",
  displayName: "OWASP VulnerableApp",
  objective:
    "Find machine-provable read-only vulnerabilities for comparison with VulnerableApp's native DAST ground truth. Prefer specific endpoints and CWE identifiers so detections and unmatched claims can be scored objectively.",
  deniedRequests: [
    { method: "GET", path: "/VulnerableApp/h2" },
    { method: "POST", path: "/VulnerableApp/scanner/benchmark" },
  ],
};
