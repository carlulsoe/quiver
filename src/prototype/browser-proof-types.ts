import type { BrowserCookie } from "./attack-surface.ts";
import type { BrowserEffectEvidence } from "./state.ts";
import type { RuntimeRequestLease } from "./runtime-safety.ts";

export interface BrowserProofProbe {
  probeId: string;
  origin: string;
  path: string;
  marker: string;
  kind: BrowserEffectEvidence["kind"];
  timeoutMs: number;
  authenticationHeaders?: Record<string, string>;
  cookies?: BrowserCookie[];
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  executablePath?: string;
  decideRequest: (method: string, path: string) => boolean;
  acquireRequest?: () => Promise<RuntimeRequestLease>;
  commitRequest?: (method: string, path: string) => boolean;
}

export interface BrowserStateTransitionProbe {
  policyId: string;
  targetOrigin: string;
  sourceOrigin: string;
  sourcePath: string;
  targetPath: string;
  method: "POST";
  timeoutMs: number;
  cookies: BrowserCookie[];
  executablePath?: string;
  decideRequest: (method: string, url: URL) => boolean;
  acquireRequest?: () => Promise<RuntimeRequestLease>;
  commitRequest?: (method: string, url: URL) => boolean;
}
