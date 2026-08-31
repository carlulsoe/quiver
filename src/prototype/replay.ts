import type { ScopedTarget } from "./scoped-target.ts";
import type { Finding, ValidationObservation } from "./state.ts";

export interface ReplayResult {
  fingerprint: string;
  observations: ValidationObservation[];
}

export async function replayFinding(target: ScopedTarget, finding: Finding): Promise<ReplayResult> {
  const observations: ValidationObservation[] = [];
  for (const request of finding.reproduction) {
    const observation = await target.request({
      path: request.path,
      authenticated: request.authenticated,
    });
    observations.push({
      status: observation.status,
      path: observation.path,
      authenticated: request.authenticated,
      body: observation.body,
      truncated: observation.truncated ?? false,
    });
  }
  return { fingerprint: finding.fingerprint, observations };
}
