import type { AllowedRequest, ScopedTarget } from "./scoped-target.ts";

export interface TargetProfile {
  id: string;
  displayName: string;
  objective: string;
  allowedRequests?: AllowedRequest[];
  authenticate?: (target: ScopedTarget) => Promise<{ authContext: string }>;
}
