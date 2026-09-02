import type {
  Finding,
  ProofArtifacts,
  ProofCheck,
  ProofPredicate,
  ValidationObservation,
} from "./state.ts";
import type { ImpactLevel } from "./state.ts";
import type { ProofPolicy } from "./target-profile.ts";
import type { ProtectedOperationManifest, TargetIdentityManifest } from "./target-manifest.ts";

export interface ProofEvaluationContext {
  policies?: readonly ProofPolicy[];
  identities?: readonly TargetIdentityManifest[];
  protectedOperations?: readonly ProtectedOperationManifest[];
  artifacts?: ProofArtifacts;
  stateResetAvailable?: boolean;
  maximumImpactLevel?: ImpactLevel;
}

export type ProofType = ProofPredicate["type"];
export type ProofEvaluationBase = Pick<
  Finding,
  "category" | "endpoint" | "method" | "impactLevel" | "reproduction"
>;
export type ProofEvaluationFinding<K extends ProofType = ProofType> = ProofEvaluationBase & {
  proof: Extract<ProofPredicate, { type: K }>;
};

export type ProofCheckHandler<K extends ProofType> = (
  finding: ProofEvaluationFinding<K>,
  observations: readonly ValidationObservation[],
  checks: ProofCheck[],
  context: ProofEvaluationContext,
) => void;

export type ProofCheckHandlers = {
  [K in ProofType]: ProofCheckHandler<K>;
};
