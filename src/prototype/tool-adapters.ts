import type { AttackSurfaceMap } from "./attack-surface.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { BrowserEffectRequest, ScopedTarget } from "./scoped-target.ts";
import type { BrowserEffectEvidence, OastCallbackEvidence } from "./state.ts";
import { browserPolicyPath, type TargetProfile } from "./target-profile.ts";

export const NON_REST_AGENT_TOOL_NAMES = [
  "map_attack_surface",
  "create_oast_probe",
  "poll_oast_probe",
  "create_browser_probe",
  "observe_browser_effect",
] as const;

export interface OastProbeOutput {
  probeId: string;
  token: string;
  url: string;
}

export interface BrowserProbeOutput {
  probeId: string;
  marker: string;
}

export interface BoundedToolAdapters {
  readonly discovery: {
    map(): Promise<AttackSurfaceMap>;
  };
  readonly oast: {
    issue(): OastProbeOutput;
    poll(input: { probeId: string; token: string }): Promise<OastCallbackEvidence | undefined>;
  };
  readonly browser: {
    issue(): BrowserProbeOutput;
    observe(input: {
      policyId: string;
      probeId: string;
    }): Promise<BrowserEffectEvidence | undefined>;
  };
}

interface BoundedToolAdapterOptions {
  target: Pick<ScopedTarget, "assertImpactLevel" | "mapAttackSurface" | "observeBrowserEffect">;
  profile: TargetProfile;
  artifacts: Pick<
    ProofArtifactStore,
    | "issueOastProbe"
    | "waitForOastCallback"
    | "issueBrowserProbe"
    | "browserProbe"
    | "recordBrowserEffect"
  >;
}

/**
 * Capability adapters for the few operations REST cannot express. Agent inputs are identifiers;
 * origins, paths, markers, credentials, browser policy, and request budgets stay code-owned.
 */
export function createBoundedToolAdapters({
  target,
  profile,
  artifacts,
}: BoundedToolAdapterOptions): BoundedToolAdapters {
  return Object.freeze({
    discovery: Object.freeze({
      map: () => target.mapAttackSurface(),
    }),
    oast: Object.freeze({
      issue() {
        target.assertImpactLevel("bounded");
        return artifacts.issueOastProbe();
      },
      poll(input: { probeId: string; token: string }) {
        return artifacts.waitForOastCallback(input.probeId, input.token);
      },
    }),
    browser: Object.freeze({
      issue() {
        target.assertImpactLevel("bounded");
        return artifacts.issueBrowserProbe();
      },
      async observe(input: { policyId: string; probeId: string }) {
        const policy = profile.proofPolicies?.find(
          (candidate) => candidate.kind === "browser-effect" && candidate.id === input.policyId,
        );
        if (policy?.kind !== "browser-effect") {
          throw new Error("Unknown browser-effect proof policy");
        }
        const probe = artifacts.browserProbe(input.probeId);
        if (!probe) throw new Error("Unknown browser proof probe");
        const request: BrowserEffectRequest = {
          probeId: input.probeId,
          marker: probe.marker,
          path: browserPolicyPath(policy, probe.marker),
          kind: policy.effect,
          actorId: policy.pageActorId,
          requestBudget: policy.requestBudget,
        };
        const evidence = await target.observeBrowserEffect(request);
        if (evidence) artifacts.recordBrowserEffect(evidence);
        return evidence;
      },
    }),
  });
}
