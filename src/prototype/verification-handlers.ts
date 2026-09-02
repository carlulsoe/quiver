import { replaceVerificationChallenge } from "./verification-challenge.ts";
import type { AllowedRequest } from "./scoped-target.ts";
import type { ActorId } from "./sessions.ts";
import type { Finding, ProofPredicate } from "./state.ts";
import type { ProofPolicy, TargetProfile } from "./target-profile.ts";

export interface VerificationProofHandler {
  readonly requiresStateReset: boolean;
  prepareFinding(finding: Finding, context: ProofHandlerContext): Finding;
  additionalAllowedRequests(finding: Finding, profile: TargetProfile): AllowedRequest[];
  additionalActorIds(finding: Finding): ActorId[];
}

export interface ProofHandlerContext {
  profile: TargetProfile;
  issueIntegerChallenge: (minimum: number, maximum: number) => number;
}

const ordinaryProofHandler: VerificationProofHandler = {
  requiresStateReset: false,
  prepareFinding: (finding) => finding,
  additionalAllowedRequests: () => [],
  additionalActorIds: () => [],
};

const stateTransitionProofHandler: VerificationProofHandler = {
  ...ordinaryProofHandler,
  requiresStateReset: true,
};

const browserVisibleEffectProofHandler: VerificationProofHandler = {
  ...ordinaryProofHandler,
  additionalActorIds: (finding) =>
    finding.proof.type === "browser-visible-effect" ? [finding.proof.pageActorId] : [],
};

const browserStateTransitionProofHandler: VerificationProofHandler = {
  ...stateTransitionProofHandler,
  additionalAllowedRequests: (finding, profile) => {
    if (finding.proof.type !== "browser-state-transition") return [];
    const policy = findProofPolicy(profile, finding.proof.policyId, "browser-state-transition");
    return policy ? [{ method: policy.method, path: policy.endpoint }] : [];
  },
  additionalActorIds: (finding) =>
    finding.proof.type === "browser-state-transition" ? [finding.proof.pageActorId] : [],
};

const commandExecutionProofHandler: VerificationProofHandler = {
  ...ordinaryProofHandler,
  prepareFinding: (finding, context) => freshCommandChallenge(finding, context),
};

const verificationProofHandlers = {
  "cross-principal-access": ordinaryProofHandler,
  "authentication-bypass": ordinaryProofHandler,
  "role-privilege-differential": ordinaryProofHandler,
  "unauthenticated-success": ordinaryProofHandler,
  "cross-principal-data-exposure": ordinaryProofHandler,
  "internal-field-exposure": ordinaryProofHandler,
  "response-differential": ordinaryProofHandler,
  "timing-differential": ordinaryProofHandler,
  "sql-semantic-differential": ordinaryProofHandler,
  "command-execution-challenge": commandExecutionProofHandler,
  "canary-retrieval": ordinaryProofHandler,
  "file-content-retrieval": ordinaryProofHandler,
  "redirect-destination": ordinaryProofHandler,
  "state-transition": stateTransitionProofHandler,
  "browser-visible-effect": browserVisibleEffectProofHandler,
  "browser-state-transition": browserStateTransitionProofHandler,
  "oast-callback": ordinaryProofHandler,
} satisfies Record<ProofPredicate["type"], VerificationProofHandler>;

export function verificationProofHandlerFor(finding: Finding): VerificationProofHandler {
  return verificationProofHandlers[finding.proof.type];
}

export function freshCommandChallenge(finding: Finding, context: ProofHandlerContext): Finding {
  if (finding.proof.type !== "command-execution-challenge") return finding;
  const proof = finding.proof;
  const policy = findProofPolicy(context.profile, proof.policyId, "command-execution-challenge");
  if (!policy) throw new Error("Unknown command-execution proof policy");
  let challenge = context.issueIntegerChallenge(policy.challengeMinimum, policy.challengeMaximum);
  if (
    !Number.isSafeInteger(challenge) ||
    challenge < policy.challengeMinimum ||
    challenge > policy.challengeMaximum
  ) {
    throw new Error("Command challenge issuer returned an out-of-policy value");
  }
  if (challenge === proof.challenge) {
    challenge = challenge === policy.challengeMaximum ? policy.challengeMinimum : challenge + 1;
  }
  return replaceVerificationChallenge(
    finding,
    proof.requestIndex,
    policy.challenge,
    String(challenge),
    { ...proof, challenge },
  );
}

export function findProofPolicy<K extends ProofPolicy["kind"]>(
  profile: TargetProfile,
  id: string,
  kind: K,
): Extract<ProofPolicy, { kind: K }> | undefined {
  return profile.proofPolicies?.find(
    (policy): policy is Extract<ProofPolicy, { kind: K }> =>
      policy.kind === kind && policy.id === id,
  );
}
