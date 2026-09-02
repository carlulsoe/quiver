import * as v from "valibot";
import type { SetupHttpObservation } from "./scoped-target.ts";
import type {
  CredentialContext,
  ManifestEnvironmentValue,
  ManifestJson,
  ManifestScalar,
} from "./target-manifest-types.ts";

export type ResolvedManifestJson =
  | string
  | number
  | boolean
  | null
  | ResolvedManifestJson[]
  | { [key: string]: ResolvedManifestJson };

const environmentValueSchema = v.object({ env: v.string(), default: v.optional(v.string()) });
const stringSchema = v.string();
const primitiveSchema = v.union([v.number(), v.boolean(), v.null()]);
const jsonObjectSchema = v.record(v.string(), v.unknown());
const manifestJsonSchema: v.GenericSchema<ManifestJson> = v.lazy(() =>
  v.union([
    v.string(),
    v.number(),
    v.boolean(),
    v.null(),
    environmentValueSchema,
    v.array(manifestJsonSchema),
    v.record(v.string(), manifestJsonSchema),
  ]),
);
const manifestObjectSchema = v.record(v.string(), manifestJsonSchema);

export function renderRecord(
  values: Record<string, string> | undefined,
  context: CredentialContext,
): Record<string, string> | undefined {
  return values
    ? Object.fromEntries(
        Object.entries(values).map(([name, value]) => [name, renderTemplate(value, context)]),
      )
    : undefined;
}

export function resolveManifestJson(
  value: ManifestJson,
  context: CredentialContext,
): ResolvedManifestJson {
  if (Array.isArray(value)) return value.map((entry) => resolveManifestJson(entry, context));
  if (isEnvironmentValue(value)) return resolveManifestValue(value, context);
  const object = v.safeParse(manifestObjectSchema, value);
  if (object.success) {
    return Object.fromEntries(
      Object.entries(object.output).map(([key, entry]) => [
        key,
        resolveManifestJson(entry, context),
      ]),
    );
  }
  const text = v.safeParse(stringSchema, value);
  return text.success ? renderTemplate(text.output, context) : v.parse(primitiveSchema, value);
}

export function resolveManifestValue(
  value: ManifestScalar,
  context: CredentialContext,
): string | number | boolean | null {
  if (!isEnvironmentValue(value)) {
    const text = v.safeParse(stringSchema, value);
    return text.success ? renderTemplate(text.output, context) : value;
  }
  const resolved = process.env[value.env] ?? value.default;
  if (resolved === undefined)
    throw new Error(`Required environment variable ${value.env} is not set`);
  return resolved;
}

export function isEnvironmentValue(value: ManifestJson): value is ManifestEnvironmentValue {
  return v.safeParse(environmentValueSchema, value).success;
}

export function renderTemplate(value: string, context: CredentialContext): string {
  return value
    .replaceAll("{{credential}}", context.credential)
    .replaceAll("{{refreshCredential}}", context.refreshCredential ?? "")
    .replace(
      /\{\{env:([A-Z_][A-Z0-9_]*)(?:\|([^}]*))?\}\}/g,
      (_match, name: string, fallback: string | undefined) => {
        const resolved = process.env[name] ?? fallback;
        if (resolved === undefined)
          throw new Error(`Required environment variable ${name} is not set`);
        return resolved;
      },
    );
}

export function readJsonPointer(
  value: SetupHttpObservation["body"],
  pointer: string,
): SetupHttpObservation["body"] {
  if (pointer === "") return value;
  if (!pointer.startsWith("/")) throw new Error(`Invalid JSON pointer ${pointer}`);
  let current = value;
  for (const segment of pointer
    .slice(1)
    .split("/")
    .map((entry) => entry.replaceAll("~1", "/").replaceAll("~0", "~"))) {
    if (Array.isArray(current)) {
      current = current[Number(segment)];
      continue;
    }
    const object = v.safeParse(jsonObjectSchema, current);
    if (!object.success) return undefined;
    current = object.output[segment];
  }
  return current;
}
