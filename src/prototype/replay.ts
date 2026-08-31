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
      method: request.method,
      headers: request.headers,
      body: request.body,
      authenticated: request.authenticated,
    });
    observations.push({
      method: observation.method ?? request.method ?? "GET",
      status: observation.status,
      path: observation.path,
      authenticated: request.authenticated,
      body: observation.body,
      truncated: observation.truncated ?? false,
      durationMs: observation.durationMs,
      sampleId: request.sampleId,
    });
  }
  return { fingerprint: finding.fingerprint, observations };
}
