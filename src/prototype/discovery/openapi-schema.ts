import type { AttackSurfaceRequestBody } from "../attack-surface.ts";
import { isCredentialFieldName } from "../security/credentials.ts";
import type { OpenApiObject, OpenApiValue } from "./openapi.ts";
import { safeExample } from "./request-evidence.ts";

export function multipartSchemaMetadata(
  document: OpenApiObject,
  rawSchema: OpenApiValue,
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
  document: OpenApiObject,
  rawSchema: OpenApiValue,
  depth = 0,
): Map<string, OpenApiValue> {
  const properties = new Map<string, OpenApiValue>();
  if (depth > 8) return properties;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return properties;
  if (isRecord(schema.properties))
    for (const entry of Object.entries(schema.properties)) properties.set(...entry);
  for (const composition of ["allOf", "oneOf", "anyOf"] as const) {
    if (!Array.isArray(schema[composition])) continue;
    for (const part of schema[composition])
      for (const entry of collectSchemaProperties(document, part, depth + 1))
        properties.set(...entry);
  }
  return properties;
}

function isBinarySchema(document: OpenApiObject, rawSchema: OpenApiValue, depth = 0): boolean {
  if (depth > 8) return false;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return false;
  if (schema.format === "binary") return true;
  if (schema.type === "array" && isBinarySchema(document, schema.items, depth + 1)) return true;
  return ["allOf", "oneOf", "anyOf"].some(
    (key) =>
      Array.isArray(schema[key]) &&
      schema[key].some((part) => isBinarySchema(document, part, depth + 1)),
  );
}

export function schemaExample(
  document: OpenApiObject,
  rawSchema: OpenApiValue,
  depth = 0,
): OpenApiValue {
  if (depth > 6) return undefined;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return undefined;
  if ("example" in schema) return safeExample(schema.example);
  if ("default" in schema) return safeExample(schema.default);
  if ("const" in schema) return safeExample(schema.const);
  if (Array.isArray(schema.enum) && schema.enum.length > 0) return safeExample(schema.enum[0]);
  for (const key of ["oneOf", "anyOf"] as const)
    if (Array.isArray(schema[key])) {
      const value = schemaExample(document, schema[key][0], depth + 1);
      if (value !== undefined) return value;
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
  if (schema.type === "string" || isString(schema.format)) {
    if (schema.format === "binary") return undefined;
    if (schema.format === "date") return "2024-01-01";
    if (schema.format === "date-time") return "2024-01-01T00:00:00Z";
    if (schema.format === "email") return "quiver@example.invalid";
    if (schema.format === "uuid") return "00000000-0000-4000-8000-000000000001";
    if (["uri", "url"].includes(String(schema.format))) return "https://example.invalid/";
    return isString(schema.pattern) ? undefined : "quiver";
  }
  return undefined;
}

export function redactExampleWithSchema(
  document: OpenApiObject,
  value: OpenApiValue,
  rawSchema: OpenApiValue,
): OpenApiValue {
  return redactSchemaValue(document, safeExample(value), rawSchema, 0);
}

function redactSchemaValue(
  document: OpenApiObject,
  value: OpenApiValue,
  rawSchema: OpenApiValue,
  depth: number,
): OpenApiValue {
  if (depth > 8 || value === undefined) return value;
  if (isBinarySchema(document, rawSchema)) return "[file content omitted]";
  if (isSensitiveSchema(document, rawSchema)) return "[redacted]";
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return value;
  let redacted: OpenApiValue = value;
  for (const key of ["allOf", "oneOf", "anyOf"] as const)
    if (Array.isArray(schema[key]))
      for (const part of schema[key])
        redacted = redactSchemaValue(document, redacted, part, depth + 1);
  if (Array.isArray(redacted) && schema.items !== undefined)
    return redacted.map((item) => redactSchemaValue(document, item, schema.items, depth + 1));
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

export function isSensitiveSchema(document: OpenApiObject, rawSchema: OpenApiValue): boolean {
  const schema = resolveLocalReference(document, rawSchema);
  const reference = isRecord(rawSchema) && isString(rawSchema.$ref) ? rawSchema.$ref : "";
  if (!isRecord(schema)) return isCredentialFieldName(reference);
  return (
    schema["x-sensitive"] === true ||
    schema.format === "password" ||
    [reference, schema.title, schema.name].filter(isString).some(isCredentialFieldName)
  );
}

export function resolveLocalReference(document: OpenApiObject, value: OpenApiValue): OpenApiValue {
  if (!isRecord(value) || !isString(value.$ref) || !value.$ref.startsWith("#/")) return value;
  let current: OpenApiValue = document;
  for (const encoded of value.$ref.slice(2).split("/")) {
    const part = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!isRecord(current) || !(part in current)) return undefined;
    current = current[part];
  }
  return current;
}

function isString(value: OpenApiValue): value is string {
  return Object.prototype.toString.call(value) === "[object String]";
}
function isRecord(value: OpenApiValue): value is OpenApiObject {
  return value instanceof Object && !Array.isArray(value);
}
