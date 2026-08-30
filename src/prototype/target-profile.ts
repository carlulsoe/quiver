import type { ScopedTarget, AllowedRequest } from "./scoped-target.ts";
import type { Candidate } from "./state.ts";

export interface CandidateAssessment {
  confirmed: boolean;
  reason: string;
  evidence: string;
  facts?: Record<string, boolean | number | string>;
}

export interface TargetProfile {
  id: string;
  displayName: string;
  objective: string;
  allowedRequests?: AllowedRequest[];
  authenticate?: (target: ScopedTarget) => Promise<{ authContext: string }>;
  validate: (target: ScopedTarget, candidate: Candidate) => Promise<CandidateAssessment>;
  createNegativeControl?: (target: ScopedTarget) => Promise<Candidate>;
}
