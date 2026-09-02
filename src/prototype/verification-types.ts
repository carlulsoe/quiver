import type { ScopedTarget } from "./scoped-target.ts";
import type {
  Finding,
  FindingInput,
  ImpactLevel,
  ProofArtifacts,
  ProofResult,
  ReproductionRequest,
  ValidationObservation,
} from "./state.ts";

export interface VerificationContext {
  observations: readonly ValidationObservation[];
}

export interface PreflightResult {
  accepted: boolean;
  proof: ProofResult;
}

export interface VerificationReplay {
  fingerprint: string;
  replayedFinding: Finding;
  observations: ValidationObservation[];
  artifacts: ProofArtifacts;
  proof: ProofResult;
}

export interface VerificationEngineOptions {
  issueIntegerChallenge?: (minimum: number, maximum: number) => number;
}

/** The single external seam for accepting and independently replaying findings. */
export interface VerificationEngine {
  preflight(submission: FindingInput, context: VerificationContext): PreflightResult;
  impactLevelFor(request: ReproductionRequest): ImpactLevel | undefined;
  replay(finding: Finding, target: ScopedTarget): Promise<VerificationReplay>;
}
