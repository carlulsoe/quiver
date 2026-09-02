import type {
  AttackSurfaceOrigin,
  AttackSurfaceRequestBody,
  AttackSurfaceScope,
} from "../attack-surface.ts";
import { isCredentialFieldName } from "../security/credentials.ts";
import { safeExample } from "./request-evidence.ts";

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

export function resolveOpenApiPrefixes(
  document: Record<string, unknown>,
  origin: string,
): string[] {
  if (typeof document.swagger === "string" && document.swagger.startsWith("2.")) {
    if (typeof document.host === "string") {
      const schemes = Array.isArray(document.schemes)
        ? document.schemes.filter((value): value is string => typeof value === "string")
        : [new URL(origin).protocol.replace(":", "")];
      try {
        if (!schemes.some((scheme) => new URL(`${scheme}://${document.host}`).origin === origin)) {
          return [];
        }
      } catch {
        return [];
      }
    }
    return [normalizePrefix(typeof document.basePath === "string" ? document.basePath : "")];
  }
  return resolveDeclaredServerPrefixes(document, origin, [""]);
}

export function resolveEffectiveOpenApiPrefixes(
  document: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>,
  origin: string,
): string[] {
  const documentPrefixes = resolveOpenApiPrefixes(document, origin);
  if (typeof document.swagger === "string" && document.swagger.startsWith("2.")) {
    return documentPrefixes;
  }
  const pathPrefixes = resolveDeclaredServerPrefixes(pathItem, origin, documentPrefixes);
  return resolveDeclaredServerPrefixes(operation, origin, pathPrefixes);
}

export function resolveOpenApiTargets(
  document: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>,
  primaryOrigin: string,
  scopes: ReadonlyMap<string, AttackSurfaceScope>,
): OpenApiTarget[] {
  if (typeof document.swagger === "string" && document.swagger.startsWith("2.")) {
    const prefix = normalizePrefix(typeof document.basePath === "string" ? document.basePath : "");
    if (typeof document.host !== "string") {
      return [{ origin: primaryOrigin, prefix, scope: "attackable" }];
    }
    const schemes = Array.isArray(document.schemes)
      ? document.schemes.filter((value): value is string => typeof value === "string")
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

  let servers: unknown = "servers" in document ? document.servers : undefined;
  if ("servers" in pathItem) servers = pathItem.servers;
  if ("servers" in operation) servers = operation.servers;
  if (servers === undefined) {
    return [{ origin: primaryOrigin, prefix: "", scope: "attackable" }];
  }
  if (!Array.isArray(servers)) return [];
  return uniqueJson(
    servers.flatMap((server): OpenApiTarget[] => {
      if (!isRecord(server) || typeof server.url !== "string" || server.url.includes("{")) {
        return [];
      }
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

export function extractOpenApiRequestBodies(
  document: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>,
): AttackSurfaceRequestBody[] {
  const requestBody = resolveLocalReference(document, operation.requestBody);
  if (isRecord(requestBody) && isRecord(requestBody.content)) {
    return Object.entries(requestBody.content).flatMap(([contentType, rawMedia]) => {
      const media = resolveLocalReference(document, rawMedia);
      if (!isRecord(media)) return [];
      const examples: unknown[] = [];
      if ("example" in media) examples.push(media.example);
      if (isRecord(media.examples)) {
        for (const rawExample of Object.values(media.examples)) {
          const example = resolveLocalReference(document, rawExample);
          if (isRecord(example) && "value" in example) examples.push(example.value);
        }
      }
      const rawSchema = media.schema;
      const schema = resolveLocalReference(document, rawSchema);
      if (isRecord(schema) && "example" in schema) examples.push(schema.example);
      const generated = schemaExample(document, schema);
      if (generated !== undefined) examples.push(generated);
      const multipart = contentType.toLowerCase().startsWith("multipart/form-data")
        ? multipartSchemaMetadata(document, rawSchema)
        : {};
      const bodies = uniqueJson(examples)
        .map((example) => redactExampleWithSchema(document, example, rawSchema))
        .filter((example) => example !== undefined)
        .map((example) => ({ contentType, source: "openapi" as const, example, ...multipart }));
      return bodies.length > 0
        ? bodies
        : [{ contentType, source: "openapi" as const, ...multipart }];
    });
  }

  const parameters = [
    ...(Array.isArray(pathItem.parameters) ? pathItem.parameters : []),
    ...(Array.isArray(operation.parameters) ? operation.parameters : []),
  ]
    .map((parameter) => resolveLocalReference(document, parameter))
    .filter(isRecord);
  const body = parameters.find((parameter) => parameter.in === "body");
  if (body) {
    const schema = resolveLocalReference(document, body.schema);
    const rawExample =
      "x-example" in body ? safeExample(body["x-example"]) : schemaExample(document, schema);
    const example =
      (typeof body.name === "string" && isCredentialFieldName(body.name)) ||
      isSensitiveSchema(document, body.schema)
        ? "[redacted]"
        : redactExampleWithSchema(document, rawExample, body.schema);
    return [
      {
        contentType:
          firstString(operation.consumes) ?? firstString(document.consumes) ?? "application/json",
        source: "openapi",
        ...(example === undefined ? {} : { example }),
      },
    ];
  }
  const form = parameters.filter((parameter) => parameter.in === "formData");
  if (form.length === 0) return [];
  const fields = form
    .filter((parameter) => parameter.type !== "file")
    .map((parameter) => parameter.name)
    .filter((name): name is string => typeof name === "string");
  const files = form.flatMap((parameter) =>
    parameter.type === "file" && typeof parameter.name === "string"
      ? [{ field: parameter.name }]
      : [],
  );
  const example = Object.fromEntries(
    form.flatMap((parameter) => {
      if (parameter.type === "file" || typeof parameter.name !== "string") return [];
      const value = schemaExample(document, parameter);
      return value === undefined
        ? []
        : [[parameter.name, redactExampleWithSchema(document, value, parameter)]];
    }),
  );
  return [
    {
      contentType:
        firstString(operation.consumes) ??
        firstString(document.consumes) ??
        (files.length > 0 ? "multipart/form-data" : "application/x-www-form-urlencoded"),
      source: "openapi",
      ...(Object.keys(example).length > 0 ? { example: safeExample(example) } : {}),
      fields,
      files,
    },
  ];
}

function exactHttpOrigin(candidate: string): string {
  const url = new URL(candidate);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error(`Discovery origin must be an HTTP(S) origin: ${candidate}`);
  }
  if (`${url.origin}/` !== url.href) {
    throw new Error(`Discovery origin must not include a path, query, or fragment: ${candidate}`);
  }
  return url.origin;
}

function resolveDeclaredServerPrefixes(
  owner: Record<string, unknown>,
  origin: string,
  inherited: string[],
): string[] {
  if (!("servers" in owner)) return inherited;
  if (!Array.isArray(owner.servers)) return [];
  const prefixes = owner.servers.flatMap((server) => {
    if (!isRecord(server) || typeof server.url !== "string" || server.url.includes("{")) return [];
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

function multipartSchemaMetadata(
  document: Record<string, unknown>,
  rawSchema: unknown,
): Pick<AttackSurfaceRequestBody, "fields" | "files"> {
  const fields: string[] = [];
  const files: Array<{ field: string }> = [];
  for (const [name, property] of collectSchemaProperties(document, rawSchema)) {
    if (isBinarySchema(document, property)) files.push({ field: name });
    else fields.push(name);
  }
  return fields.length > 0 || files.length > 0 ? { fields, files } : {};
}

function collectSchemaProperties(
  document: Record<string, unknown>,
  rawSchema: unknown,
  depth = 0,
): Map<string, unknown> {
  const properties = new Map<string, unknown>();
  if (depth > 8) return properties;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return properties;
  if (isRecord(schema.properties)) {
    for (const [name, property] of Object.entries(schema.properties)) {
      properties.set(name, property);
    }
  }
  for (const composition of ["allOf", "oneOf", "anyOf"] as const) {
    if (!Array.isArray(schema[composition])) continue;
    for (const part of schema[composition]) {
      for (const [name, property] of collectSchemaProperties(document, part, depth + 1)) {
        properties.set(name, property);
      }
    }
  }
  return properties;
}

function isBinarySchema(document: Record<string, unknown>, rawSchema: unknown, depth = 0): boolean {
  if (depth > 8) return false;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return false;
  if (schema.format === "binary") return true;
  if (schema.type === "array" && isBinarySchema(document, schema.items, depth + 1)) return true;
  return ["allOf", "oneOf", "anyOf"].some(
    (composition) =>
      Array.isArray(schema[composition]) &&
      schema[composition].some((part: unknown) => isBinarySchema(document, part, depth + 1)),
  );
}

function schemaExample(document: Record<string, unknown>, rawSchema: unknown, depth = 0): unknown {
  if (depth > 6) return undefined;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return undefined;
  if ("example" in schema) return safeExample(schema.example);
  if ("default" in schema) return safeExample(schema.default);
  if ("const" in schema) return safeExample(schema.const);
  if (Array.isArray(schema.enum) && schema.enum.length > 0) return safeExample(schema.enum[0]);
  for (const composition of ["oneOf", "anyOf"] as const) {
    if (Array.isArray(schema[composition])) {
      const value = schemaExample(document, schema[composition][0], depth + 1);
      if (value !== undefined) return value;
    }
  }
  if (Array.isArray(schema.allOf)) {
    const values = schema.allOf.map((part) => schemaExample(document, part, depth + 1));
    if (values.every(isRecord)) return Object.assign({}, ...values);
  }
  if (schema.type === "object" || isRecord(schema.properties)) {
    if (!isRecord(schema.properties)) return {};
    return Object.fromEntries(
      Object.entries(schema.properties)
        .slice(0, 24)
        .flatMap(([name, property]) => {
          const value = schemaExample(document, property, depth + 1);
          return value === undefined ? [] : [[name, value]];
        }),
    );
  }
  if (schema.type === "array") {
    const value = schemaExample(document, schema.items, depth + 1);
    return value === undefined ? [] : [value];
  }
  if (schema.type === "integer" || schema.type === "number") return schema.minimum ?? 1;
  if (schema.type === "boolean") return true;
  if (schema.type === "null") return null;
  if (schema.type === "string" || typeof schema.format === "string") {
    if (schema.format === "binary") return undefined;
    if (schema.format === "date") return "2024-01-01";
    if (schema.format === "date-time") return "2024-01-01T00:00:00Z";
    if (schema.format === "email") return "quiver@example.invalid";
    if (schema.format === "uuid") return "00000000-0000-4000-8000-000000000001";
    if (["uri", "url"].includes(String(schema.format))) return "https://example.invalid/";
    return typeof schema.pattern === "string" ? undefined : "quiver";
  }
  return undefined;
}

function isSensitiveSchema(document: Record<string, unknown>, rawSchema: unknown): boolean {
  const schema = resolveLocalReference(document, rawSchema);
  const reference = isRecord(rawSchema) && typeof rawSchema.$ref === "string" ? rawSchema.$ref : "";
  if (!isRecord(schema)) return isCredentialFieldName(reference);
  if (schema["x-sensitive"] === true || schema.format === "password") return true;
  return [reference, schema.title, schema.name]
    .filter((value): value is string => typeof value === "string")
    .some(isCredentialFieldName);
}

function redactExampleWithSchema(
  document: Record<string, unknown>,
  value: unknown,
  rawSchema: unknown,
): unknown {
  return redactSchemaValue(document, safeExample(value), rawSchema, 0);
}

function redactSchemaValue(
  document: Record<string, unknown>,
  value: unknown,
  rawSchema: unknown,
  depth: number,
): unknown {
  if (depth > 8 || value === undefined) return value;
  if (isBinarySchema(document, rawSchema)) return "[file content omitted]";
  if (isSensitiveSchema(document, rawSchema)) return "[redacted]";
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return value;
  let redacted: unknown = value;
  for (const composition of ["allOf", "oneOf", "anyOf"] as const) {
    if (!Array.isArray(schema[composition])) continue;
    for (const part of schema[composition]) {
      redacted = redactSchemaValue(document, redacted, part, depth + 1);
    }
  }
  if (Array.isArray(redacted) && schema.items !== undefined) {
    return redacted.map((item) => redactSchemaValue(document, item, schema.items, depth + 1));
  }
  if (!isRecord(redacted)) return redacted;
  const properties = isRecord(schema.properties) ? schema.properties : {};
  return Object.fromEntries(
    Object.entries(redacted).map(([key, child]) => {
      if (isCredentialFieldName(key)) return [key, "[redacted]"];
      const childSchema = properties[key] ?? schema.additionalProperties;
      return [
        key,
        childSchema === undefined
          ? child
          : redactSchemaValue(document, child, childSchema, depth + 1),
      ];
    }),
  );
}

function resolveLocalReference(document: Record<string, unknown>, value: unknown): unknown {
  if (!isRecord(value) || typeof value.$ref !== "string" || !value.$ref.startsWith("#/")) {
    return value;
  }
  let current: unknown = document;
  for (const encoded of value.$ref.slice(2).split("/")) {
    const part = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!isRecord(current) || !(part in current)) return undefined;
    current = current[part];
  }
  return current;
}

function uniqueJson<T>(values: readonly T[]): T[] {
  return values.filter(
    (value, index) =>
      values.findIndex((candidate) => JSON.stringify(candidate) === JSON.stringify(value)) ===
      index,
  );
}

function firstString(value: unknown): string | undefined {
  return Array.isArray(value)
    ? value.find((entry): entry is string => typeof entry === "string")
    : undefined;
}

function isRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
