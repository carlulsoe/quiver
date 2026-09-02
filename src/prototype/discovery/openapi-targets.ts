import type { AttackSurfaceOrigin, AttackSurfaceScope } from "../attack-surface.ts";
import type { OpenApiObject, OpenApiValue } from "./openapi.ts";

export interface OpenApiTarget {
  origin: string;
  prefix: string;
  scope: AttackSurfaceScope;
}

export function normalizeAttackSurfaceOrigins(
  primaryOrigin: string,
  configured: readonly AttackSurfaceOrigin[] = [],
): ReadonlyMap<string, AttackSurfaceScope> {
  const primary = exactHttpOrigin(primaryOrigin);
  const scopes = new Map<string, AttackSurfaceScope>();
  for (const candidate of configured) {
    const origin = exactHttpOrigin(candidate.origin);
    if (scopes.get(origin) !== "attackable") scopes.set(origin, candidate.scope);
  }
  scopes.set(primary, "attackable");
  return scopes;
}

export function resolveOpenApiPrefixes(document: OpenApiObject, origin: string): string[] {
  if (isString(document.swagger) && document.swagger.startsWith("2.")) {
    if (isString(document.host)) {
      const schemes = Array.isArray(document.schemes)
        ? document.schemes.filter(isString)
        : [new URL(origin).protocol.replace(":", "")];
      try {
        if (!schemes.some((scheme) => new URL(`${scheme}://${document.host}`).origin === origin))
          return [];
      } catch {
        return [];
      }
    }
    return [normalizePrefix(isString(document.basePath) ? document.basePath : "")];
  }
  return resolveDeclaredServerPrefixes(document, origin, [""]);
}

export function resolveEffectiveOpenApiPrefixes(
  document: OpenApiObject,
  pathItem: OpenApiObject,
  operation: OpenApiObject,
  origin: string,
): string[] {
  const documentPrefixes = resolveOpenApiPrefixes(document, origin);
  if (isString(document.swagger) && document.swagger.startsWith("2.")) return documentPrefixes;
  return resolveDeclaredServerPrefixes(
    operation,
    origin,
    resolveDeclaredServerPrefixes(pathItem, origin, documentPrefixes),
  );
}

export function resolveOpenApiTargets(
  document: OpenApiObject,
  pathItem: OpenApiObject,
  operation: OpenApiObject,
  primaryOrigin: string,
  scopes: ReadonlyMap<string, AttackSurfaceScope>,
): OpenApiTarget[] {
  if (isString(document.swagger) && document.swagger.startsWith("2.")) {
    const prefix = normalizePrefix(isString(document.basePath) ? document.basePath : "");
    if (!isString(document.host)) return [{ origin: primaryOrigin, prefix, scope: "attackable" }];
    const schemes = Array.isArray(document.schemes)
      ? document.schemes.filter(isString)
      : [new URL(primaryOrigin).protocol.replace(":", "")];
    return schemes.flatMap((scheme): OpenApiTarget[] => {
      try {
        const origin = new URL(`${scheme}://${document.host}`).origin;
        const scope = scopes.get(origin);
        return scope ? [{ origin, prefix, scope }] : [];
      } catch {
        return [];
      }
    });
  }
  let servers: OpenApiValue = document.servers;
  if ("servers" in pathItem) servers = pathItem.servers;
  if ("servers" in operation) servers = operation.servers;
  if (servers === undefined) return [{ origin: primaryOrigin, prefix: "", scope: "attackable" }];
  if (!Array.isArray(servers)) return [];
  return uniqueJson(
    servers.flatMap((server): OpenApiTarget[] => {
      if (!isRecord(server) || !isString(server.url) || server.url.includes("{")) return [];
      try {
        const url = new URL(server.url, primaryOrigin);
        const scope = scopes.get(url.origin);
        return scope ? [{ origin: url.origin, prefix: normalizePrefix(url.pathname), scope }] : [];
      } catch {
        return [];
      }
    }),
  );
}

function exactHttpOrigin(candidate: string): string {
  const url = new URL(candidate);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password)
    throw new Error(`Discovery origin must be an HTTP(S) origin: ${candidate}`);
  if (`${url.origin}/` !== url.href)
    throw new Error(`Discovery origin must not include a path, query, or fragment: ${candidate}`);
  return url.origin;
}

function resolveDeclaredServerPrefixes(
  owner: OpenApiObject,
  origin: string,
  inherited: string[],
): string[] {
  if (!("servers" in owner)) return inherited;
  if (!Array.isArray(owner.servers)) return [];
  const prefixes = owner.servers.flatMap((server) => {
    if (!isRecord(server) || !isString(server.url) || server.url.includes("{")) return [];
    try {
      const url = new URL(server.url, origin);
      return url.origin === origin ? [normalizePrefix(url.pathname)] : [];
    } catch {
      return [];
    }
  });
  return [...new Set(prefixes)];
}

function normalizePrefix(value: string): string {
  const prefix = `/${value}`.replaceAll(/\/{2,}/g, "/").replace(/\/$/, "");
  return prefix === "/" ? "" : prefix;
}
function uniqueJson<T>(values: readonly T[]): T[] {
  return values.filter(
    (value, index) =>
      values.findIndex((candidate) => JSON.stringify(candidate) === JSON.stringify(value)) ===
      index,
  );
}
function isString(value: OpenApiValue): value is string {
  return Object.prototype.toString.call(value) === "[object String]";
}
function isRecord(value: OpenApiValue): value is OpenApiObject {
  return value instanceof Object && !Array.isArray(value);
}
