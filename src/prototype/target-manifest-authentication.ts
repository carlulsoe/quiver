import * as v from "valibot";
import type { ScopedTarget } from "./scoped-target.ts";
import { actorIds, type ActorId, type StoredSession } from "./sessions.ts";
import { runExchange } from "./target-manifest-exchange.ts";
import { materializeSession } from "./target-manifest-session.ts";
import type {
  CredentialSource,
  MaterializedCredentials,
  SessionAdapterManifest,
  TargetIdentityManifest,
  TargetManifest,
} from "./target-manifest-types.ts";
import { assertValidTargetManifest } from "./target-manifest-validation.ts";
import { resolveManifestValue } from "./target-manifest-values.ts";

const nonEmptyStringSchema = v.pipe(v.string(), v.minLength(1));

export async function authenticateTargetManifest(
  target: ScopedTarget,
  manifest: TargetManifest,
  options: { now?: () => number; actorIds?: readonly ActorId[] } = {},
): Promise<{ authContext: string }> {
  assertValidTargetManifest(manifest);
  const requestedActors = options.actorIds ? new Set(options.actorIds) : undefined;
  const authenticated = manifest.identities.filter(
    (identity): identity is TargetIdentityManifest & { authentication: SessionAdapterManifest } =>
      identity.authentication !== undefined &&
      (!requestedActors || requestedActors.has(identity.id)),
  );
  const resolvedActors = new Set(authenticated.map(({ id }) => id));
  const unknownActors = [...(requestedActors ?? [])].filter(
    (actorId) => actorId !== actorIds.anonymous && !resolvedActors.has(actorId),
  );
  if (unknownActors.length > 0) {
    throw new Error(
      `Target manifest ${manifest.id} has no authentication for ${unknownActors.join(", ")}`,
    );
  }
  for (const identity of authenticated) {
    target.setSessionProvider(
      identity.id,
      createSessionProvider(target, identity, options.now ?? Date.now),
    );
  }
  // Fail setup early and deterministically instead of discovering a bad principal mid-campaign.
  for (const identity of authenticated) await target.sessions.acquire(identity.id);
  return {
    authContext: manifest.authenticationContext ?? authenticated.map(({ id }) => id).join(","),
  };
}

export function createSessionProvider(
  target: ScopedTarget,
  identity: TargetIdentityManifest & { authentication: SessionAdapterManifest },
  now: () => number,
): () => Promise<StoredSession> {
  const adapter = identity.authentication;
  let credentials: MaterializedCredentials | undefined;
  let pending: Promise<StoredSession> | undefined;
  return async () => {
    if (credentials && !isExpiring(credentials, adapter.refreshBeforeMs ?? 0, now())) {
      return materializeSession(adapter, credentials, target.origin);
    }
    pending ??= (async () => {
      const exchange = credentials && adapter.refresh ? adapter.refresh : adapter.login;
      const next = exchange
        ? await runExchange(target, identity, exchange, credentials, now())
        : staticCredentials(adapter.credential!);
      credentials = {
        ...next,
        refreshCredential: next.refreshCredential ?? credentials?.refreshCredential,
      };
      return materializeSession(adapter, credentials, target.origin);
    })().finally(() => {
      pending = undefined;
    });
    return pending;
  };
}

export function staticCredentials(source: CredentialSource): MaterializedCredentials {
  if (source.location !== "literal") throw new Error("Static credentials must be literal");
  const credential = resolveManifestValue(source.value, { credential: "" });
  const parsed = v.safeParse(nonEmptyStringSchema, credential);
  if (!parsed.success) {
    throw new Error("Static authentication credential did not resolve to a non-empty string");
  }
  return { credential: parsed.output };
}

export function isExpiring(
  credentials: MaterializedCredentials,
  refreshBeforeMs: number,
  now: number,
): boolean {
  return credentials.expiresAt !== undefined && now >= credentials.expiresAt - refreshBeforeMs;
}
