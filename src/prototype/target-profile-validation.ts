import { assertValidTargetManifest } from "./target-manifest.ts";
import {
  browserChallengeValues,
  isAbsoluteHttpUrl,
  isExactOrigin,
  isOriginRelativePath,
  safePolicyRegex,
  sameChallenge,
} from "./target-profile-browser.ts";
import type { ProofPolicy, TargetProfile } from "./target-profile-types.ts";

export function assertValidTargetProfile(profile: TargetProfile): void {
  if (profile.manifest) assertValidTargetManifest(profile.manifest);
  if (
    profile.prepareValidation &&
    (!Number.isInteger(profile.validationResetRequestBudget) ||
      (profile.validationResetRequestBudget ?? -1) < 0)
  ) {
    throw new Error("Profiles with prepareValidation must declare validationResetRequestBudget");
  }
  if (
    profile.callbackConfigurationFingerprint !== undefined &&
    profile.callbackConfigurationFingerprint.trim().length === 0
  ) {
    throw new Error("callbackConfigurationFingerprint must not be empty");
  }
  for (const policy of profile.proofPolicies ?? []) {
    validateProofPolicy(policy, profile);
  }
}

type ProofPolicyValidator<K extends ProofPolicy["kind"]> = (
  policy: Extract<ProofPolicy, { kind: K }>,
  profile: TargetProfile,
) => void;

type ProofPolicyValidators = {
  [K in ProofPolicy["kind"]]: ProofPolicyValidator<K>;
};

const proofPolicyValidators = {
  canary: () => undefined,
  "state-transition": (policy) => {
    if (
      !["POST", "PUT", "PATCH"].includes(policy.method) ||
      !["GET", "HEAD"].includes(policy.readMethod)
    ) {
      throw new Error(
        `State-transition policy ${policy.id} must use POST/PUT/PATCH with a GET/HEAD state read`,
      );
    }
  },
  "browser-effect": (policy) => {
    if (
      !Number.isInteger(policy.requestBudget) ||
      policy.requestBudget < 1 ||
      policy.requestBudget > 20
    ) {
      throw new Error(`Browser-effect policy ${policy.id} requestBudget must be from 1 to 20`);
    }
    if (
      policy.challenge.template !== policy.payloadTemplate ||
      policy.challenge.template.split("{{challenge}}").length !== 2
    ) {
      throw new Error(
        `Browser-effect policy ${policy.id} challenge must use its payloadTemplate once`,
      );
    }
    if (
      (policy.workflow === "stored" &&
        (!["POST", "PUT", "PATCH"].includes(policy.method) ||
          policy.challenge.location === "fragment" ||
          policy.pageChallenge !== undefined)) ||
      (policy.workflow === "dom" &&
        (policy.method !== "GET" ||
          policy.challenge.location !== "fragment" ||
          policy.pageChallenge?.location !== "fragment"))
    ) {
      throw new Error(
        `Browser-effect policy ${policy.id} must declare a closed stored or fragment-only DOM workflow`,
      );
    }
    if (
      policy.pageChallenge &&
      (!["query", "fragment"].includes(policy.pageChallenge.location) ||
        !sameChallenge(policy.challenge, policy.pageChallenge) ||
        policy.pageChallenge.template.split("{{challenge}}").length !== 2 ||
        browserChallengeValues(policy.pagePath, policy.pageChallenge).length !== 1)
    ) {
      throw new Error(
        `Browser-effect policy ${policy.id} pageChallenge must replace one declared URL parameter`,
      );
    }
  },
  "browser-state-transition": (policy, profile) => {
    if (
      !Number.isInteger(policy.requestBudget) ||
      policy.requestBudget < 2 ||
      policy.requestBudget > 20 ||
      policy.method !== "POST" ||
      !["GET", "HEAD"].includes(policy.readMethod) ||
      !profile.prepareValidation ||
      !Number.isInteger(profile.validationResetRequestBudget) ||
      policy.pageActorId === "anonymous" ||
      !isExactOrigin(policy.sourceOrigin) ||
      !isOriginRelativePath(policy.sourcePath) ||
      !profile.attackSurfaceOrigins?.some(
        ({ origin, scope }) =>
          new URL(origin).origin === policy.sourceOrigin && scope === "visit-only",
      )
    ) {
      throw new Error(
        `Browser-state-transition policy ${policy.id} requires an authenticated configured visit-only origin, a fresh-state reset hook, and a request budget from 2 to 20`,
      );
    }
  },
  "file-content": (policy) => {
    if (
      policy.request.value.length === 0 ||
      (policy.request.location === "json-body" &&
        !["POST", "PUT", "PATCH"].includes(policy.method)) ||
      safePolicyRegex(policy.contentTypePattern) === undefined
    ) {
      throw new Error(
        `File-content policy ${policy.id} must declare a valid request and media type`,
      );
    }
  },
  redirect: (policy) => {
    if (
      policy.challenge.template.split("{{challenge}}").length !== 2 ||
      !isAbsoluteHttpUrl(policy.destination)
    ) {
      throw new Error(
        `Redirect policy ${policy.id} must bind one absolute HTTP(S) destination challenge`,
      );
    }
  },
  oast: (policy) => {
    if (policy.challenge.template.split("{{challenge}}").length !== 2) {
      throw new Error(`OAST policy ${policy.id} challenge must substitute the callback once`);
    }
  },
  "sql-semantic-differential": (policy) => {
    if (
      policy.mutation.controlValue === policy.mutation.probeValue ||
      Object.is(policy.response.controlValue, policy.response.probeValue)
    ) {
      throw new Error(
        `SQL semantic-differential policy ${policy.id} must use distinct request and response values`,
      );
    }
  },
  "command-execution-challenge": (policy) => {
    if (
      policy.challenge.template.split("{{challenge}}").length !== 2 ||
      !Number.isSafeInteger(policy.multiplier) ||
      policy.multiplier === 0 ||
      !Number.isSafeInteger(policy.addend) ||
      !Number.isSafeInteger(policy.challengeMinimum) ||
      !Number.isSafeInteger(policy.challengeMaximum) ||
      policy.challengeMinimum < 1 ||
      policy.challengeMinimum >= policy.challengeMaximum ||
      !Number.isSafeInteger(policy.challengeMinimum * policy.multiplier + policy.addend) ||
      !Number.isSafeInteger(policy.challengeMaximum * policy.multiplier + policy.addend) ||
      policy.outputPrefix.length === 0
    ) {
      throw new Error(
        `Command-execution policy ${policy.id} must declare one bounded arithmetic challenge`,
      );
    }
  },
} satisfies ProofPolicyValidators;

function validateProofPolicy<K extends ProofPolicy["kind"]>(
  policy: Extract<ProofPolicy, { kind: K }>,
  profile: TargetProfile,
): void {
  const validator = proofPolicyValidators[policy.kind] as ProofPolicyValidator<K>;
  validator(policy, profile);
}
