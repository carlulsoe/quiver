import type { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

export interface ReplayObservation {
  status: number;
  path: string;
  body: unknown;
  truncated: boolean;
}

export interface ReplayResult {
  fingerprint: string;
  observations: ReplayObservation[];
}

export async function replayFinding(target: ScopedTarget, finding: Finding): Promise<ReplayResult> {
  const observations: ReplayObservation[] = [];
  for (const request of finding.reproduction) {
    const observation = await target.request({
      path: request.path,
      authenticated: request.authenticated,
    });
    observations.push({
      status: observation.status,
      path: observation.path,
      body: observation.body,
      truncated: observation.truncated ?? false,
    });
  }
  return { fingerprint: finding.fingerprint, observations };
}
