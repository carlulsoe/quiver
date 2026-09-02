import { actorIds, type ActorId } from "./sessions.ts";
import type {
  AuthenticationExchangeManifest,
  SessionAdapterManifest,
  TargetIdentityManifest,
  TargetManifest,
} from "./target-manifest-types.ts";

export function manifestActorIds(manifest: TargetManifest): ActorId[] {
  return manifest.identities
    .map(({ id }) => id)
    .filter((actorId) => actorId !== actorIds.anonymous);
}

export function assertValidTargetManifest(manifest: TargetManifest): void {
  if (manifest.schemaVersion !== 1) throw new Error("Target manifests must use schemaVersion 1");
  const identities = new Map<ActorId, TargetIdentityManifest>();
  for (const identity of manifest.identities) {
    if (identities.has(identity.id)) {
      throw new Error(
        `Target manifest ${manifest.id} declares actor ${identity.id} more than once`,
      );
    }
    identities.set(identity.id, identity);
    if (identity.role === "anonymous" && identity.id !== actorIds.anonymous) {
      throw new Error("The anonymous identity must use the anonymous actor ID");
    }
    if (
      identity.id === actorIds.anonymous &&
      (identity.role !== "anonymous" || identity.authentication)
    ) {
      throw new Error("The anonymous actor cannot declare authentication");
    }
    if (identity.id !== actorIds.anonymous && !identity.authentication) {
      throw new Error(`Actor ${identity.id} must declare a session adapter`);
    }
    if (identity.authentication) assertValidSessionAdapter(identity.id, identity.authentication);
  }
  if (!identities.has(actorIds.anonymous)) {
    throw new Error(`Target manifest ${manifest.id} must declare the anonymous actor`);
  }
  for (const operation of manifest.scope.protectedOperations ?? []) {
    if (operation.authorizedActors.length === 0) {
      throw new Error(
        `Protected operation ${operation.method} ${operation.path} has no authorized actors`,
      );
    }
    for (const actorId of operation.authorizedActors) {
      if (!identities.has(actorId)) {
        throw new Error(
          `Protected operation ${operation.method} ${operation.path} references unknown actor ${actorId}`,
        );
      }
    }
  }
  const setupOperations = new Set(
    (manifest.scope.setupOperations ?? []).map(({ method, path }) => `${method} ${path}`),
  );
  for (const identity of manifest.identities) {
    const authentication = identity.authentication;
    if (!authentication) continue;
    for (const exchange of [authentication.login, authentication.refresh].filter(
      (candidate): candidate is AuthenticationExchangeManifest => candidate !== undefined,
    )) {
      const key = `${exchange.request.method} ${exchange.request.path}`;
      if (!setupOperations.has(key)) {
        throw new Error(
          `Authentication operation ${key} must be declared in scope.setupOperations`,
        );
      }
    }
  }
}

export function assertValidSessionAdapter(actorId: ActorId, adapter: SessionAdapterManifest): void {
  if ((adapter.refreshBeforeMs ?? 0) < 0) {
    throw new Error(`Actor ${actorId} refreshBeforeMs must be non-negative`);
  }
  if (!adapter.login && !adapter.credential) {
    throw new Error(`Actor ${actorId} must declare login or credential`);
  }
  if (adapter.login && adapter.credential) {
    throw new Error(`Actor ${actorId} cannot declare both login and credential`);
  }
  if (adapter.credential && adapter.credential.location !== "literal") {
    throw new Error(`Actor ${actorId} static credential must use a literal source`);
  }
  if (adapter.refresh && !adapter.login?.refreshCredential) {
    throw new Error(`Actor ${actorId} needs a login refreshCredential when refresh is configured`);
  }
  for (const exchange of [adapter.login, adapter.refresh].filter(
    (candidate): candidate is AuthenticationExchangeManifest => candidate !== undefined,
  )) {
    if (exchange.request.path.includes("{{")) {
      throw new Error(`Actor ${actorId} authentication request paths must be static`);
    }
    if (exchange.expiresAfterMs !== undefined && exchange.expiresAfterMs <= 0) {
      throw new Error(`Actor ${actorId} expiresAfterMs must be positive`);
    }
    if (exchange.expectedStatuses?.length === 0) {
      throw new Error(`Actor ${actorId} expectedStatuses must not be empty`);
    }
  }
  if (adapter.kind === "browser-login" && Object.keys(adapter.session).length === 0) {
    throw new Error(`Actor ${actorId} browser-login session must declare browser material`);
  }
}
