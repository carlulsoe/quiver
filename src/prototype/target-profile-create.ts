import type { AllowedRequest, ScopedTarget } from "./scoped-target.ts";
import type { ActorId } from "./sessions.ts";
import {
  assertValidTargetManifest,
  authenticateTargetManifest,
  manifestActorIds,
  type TargetManifest,
} from "./target-manifest.ts";
import type { TargetProfile, TargetProfileExtensions } from "./target-profile-types.ts";

export function createTargetProfile(
  manifest: TargetManifest,
  extensions: TargetProfileExtensions = {},
): TargetProfile {
  assertValidTargetManifest(manifest);
  const actorIds = manifestActorIds(manifest);
  const setupRequests = [...(manifest.scope.setupOperations ?? [])];
  const allowedRequests = uniqueOperations([
    ...setupRequests,
    ...(manifest.scope.protectedOperations ?? []).map(({ method, path }) => ({ method, path })),
  ]);
  const extensionCallbacks = extensionsContainCallbacks(extensions);
  const callbackConfigurationFingerprint =
    extensions.callbackConfigurationFingerprint ??
    (extensionCallbacks ? undefined : `manifest-derived:${manifest.schemaVersion}`);
  const profile: TargetProfile = {
    id: manifest.id,
    displayName: manifest.displayName,
    objective: manifest.objective,
    allowedRequests: allowedRequests.length > 0 ? allowedRequests : undefined,
    setupRequests: setupRequests.length > 0 ? setupRequests : undefined,
    deniedRequests: manifest.scope.deniedOperations
      ? [...manifest.scope.deniedOperations]
      : undefined,
    protectedOperations: manifest.scope.protectedOperations
      ? [...manifest.scope.protectedOperations]
      : undefined,
    maximumImpactLevel: manifest.scope.maximumImpactLevel,
    actorIds,
    reproductionAuthentication: manifest.reproductionAuthentication,
    manifest,
    ...extensions,
  };
  if (actorIds.length > 0) {
    profile.authenticate = (target: ScopedTarget, requestedActorIds?: readonly ActorId[]) =>
      authenticateTargetManifest(target, manifest, { actorIds: requestedActorIds });
  }
  if (callbackConfigurationFingerprint) {
    profile.callbackConfigurationFingerprint = callbackConfigurationFingerprint;
  }
  return profile;
}

function uniqueOperations(operations: AllowedRequest[]): AllowedRequest[] {
  return [
    ...new Map(
      operations.map((operation) => [`${operation.method} ${operation.path}`, operation]),
    ).values(),
  ];
}

function extensionsContainCallbacks(extensions: TargetProfileExtensions): boolean {
  return (
    extensions.prepareValidation !== undefined ||
    extensions.proofPolicies?.some(
      (policy) =>
        (policy.kind === "canary" || policy.kind === "file-content") && policy.verify !== undefined,
    ) === true
  );
}
