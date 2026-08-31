import type { AllowedRequest, DeniedRequest, ScopedTarget } from "./scoped-target.ts";

export interface ReproductionAuthentication {
  description: string;
  commands: string[];
}

export interface TargetProfile {
  id: string;
  displayName: string;
  objective: string;
  allowedRequests?: AllowedRequest[];
  deniedRequests?: DeniedRequest[];
  authenticate?: (target: ScopedTarget) => Promise<{ authContext: string }>;
  reproductionAuthentication?: ReproductionAuthentication;
}
