import * as v from "valibot";
import type { ScopedTarget, SetupHttpObservation } from "./scoped-target.ts";
import type {
  AuthenticationExchangeManifest,
  CredentialContext,
  CredentialSource,
  MaterializedCredentials,
  TargetIdentityManifest,
} from "./target-manifest-types.ts";
import {
  resolveManifestJson,
  resolveManifestValue,
  readJsonPointer,
} from "./target-manifest-values.ts";

const nonEmptyStringSchema = v.pipe(v.string(), v.minLength(1));

export async function runExchange(
  target: ScopedTarget,
  identity: TargetIdentityManifest,
  exchange: AuthenticationExchangeManifest,
  previous: MaterializedCredentials | undefined,
  now: number,
): Promise<MaterializedCredentials> {
  const context: CredentialContext = previous ?? { credential: "" };
  const observation = await target.setupRequest({
    method: exchange.request.method,
    path: exchange.request.path,
    headers: exchange.request.headers
      ? Object.fromEntries(
          Object.entries(exchange.request.headers).map(([name, value]) => [
            name,
            String(resolveManifestValue(value, context)),
          ]),
        )
      : undefined,
    body:
      exchange.request.body === undefined
        ? undefined
        : JSON.stringify(resolveManifestJson(exchange.request.body, context)),
  });
  const expectedStatuses = exchange.expectedStatuses ?? [200, 201, 204];
  if (!expectedStatuses.includes(observation.status)) {
    throw new Error(
      `${identity.label} authentication failed with status ${observation.status}; expected ${expectedStatuses.join(", ")}`,
    );
  }
  const credentials: MaterializedCredentials = {
    credential: readCredential(exchange.credential, observation, context),
  };
  if (exchange.refreshCredential) {
    credentials.refreshCredential = readCredential(
      exchange.refreshCredential,
      observation,
      context,
    );
  }
  if (exchange.expiresAfterMs !== undefined) credentials.expiresAt = now + exchange.expiresAfterMs;
  return credentials;
}

export function readCredential(
  source: CredentialSource,
  observation: SetupHttpObservation,
  context: CredentialContext,
): string {
  let value: unknown;
  if (source.location === "header") value = observation.headers[source.name.toLowerCase()];
  else if (source.location === "cookie") {
    value = readResponseCookie(observation.headers["set-cookie"], source.name);
  } else if (source.location === "literal") value = resolveManifestValue(source.value, context);
  else value = readJsonPointer(observation.body, source.pointer);
  const parsed = v.safeParse(nonEmptyStringSchema, value);
  if (!parsed.success) {
    const location = source.location === "body" ? source.pointer : source.location;
    throw new Error(`Authentication credential ${location} did not resolve to a non-empty string`);
  }
  return parsed.output;
}

export function readResponseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?:^|,\\s*)${escapedName}=([^;,]*)`).exec(header)?.[1];
}
