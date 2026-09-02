import type { AttackSurfaceRequestBody } from "../attack-surface.ts";
import { isCredentialFieldName } from "../security/credentials.ts";
import { safeExample } from "./request-evidence.ts";
import {
  isSensitiveSchema,
  multipartSchemaMetadata,
  redactExampleWithSchema,
  resolveLocalReference,
  schemaExample,
} from "./openapi-schema.ts";

export {
  normalizeAttackSurfaceOrigins,
  resolveEffectiveOpenApiPrefixes,
  resolveOpenApiPrefixes,
  resolveOpenApiTargets,
} from "./openapi-targets.ts";
export type { OpenApiTarget } from "./openapi-targets.ts";

export type OpenApiValue =
  | undefined
  | null
  | boolean
  | number
  | string
  | OpenApiValue[]
  | OpenApiObject;
export interface OpenApiObject {
  [key: string]: OpenApiValue;
}

export function extractOpenApiRequestBodies(
  document: OpenApiObject,
  pathItem: OpenApiObject,
  operation: OpenApiObject,
): AttackSurfaceRequestBody[] {
  const requestBody = resolveLocalReference(document, operation.requestBody);
  if (isRecord(requestBody) && isRecord(requestBody.content)) {
    return Object.entries(requestBody.content).flatMap(([contentType, rawMedia]) => {
      const media = resolveLocalReference(document, rawMedia);
      if (!isRecord(media)) return [];
      const examples: OpenApiValue[] = [];
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
      (isString(body.name) && isCredentialFieldName(body.name)) ||
      isSensitiveSchema(document, body.schema)
        ? "[redacted]"
        : redactExampleWithSchema(document, rawExample, body.schema);
    return [
      {
        contentType:
          firstString(operation.consumes) ?? firstString(document.consumes) ?? "application/json",
        source: "openapi",
        example,
      },
    ];
  }
  const form = parameters.filter((parameter) => parameter.in === "formData");
  if (form.length === 0) return [];
  const fields = form
    .filter((parameter) => parameter.type !== "file")
    .map((parameter) => parameter.name)
    .filter(isString);
  const files = form.flatMap((parameter) =>
    parameter.type === "file" && isString(parameter.name) ? [{ field: parameter.name }] : [],
  );
  const example = Object.fromEntries(
    form.flatMap((parameter) => {
      if (parameter.type === "file" || !isString(parameter.name)) return [];
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
      example: Object.keys(example).length > 0 ? safeExample(example) : undefined,
      fields,
      files,
    },
  ];
}

function uniqueJson<T>(values: readonly T[]): T[] {
  return values.filter(
    (value, index) =>
      values.findIndex((candidate) => JSON.stringify(candidate) === JSON.stringify(value)) ===
      index,
  );
}

function firstString(value: OpenApiValue | undefined): string | undefined {
  return Array.isArray(value) ? value.find(isString) : undefined;
}

function isString(value: OpenApiValue | undefined): value is string {
  return Object.prototype.toString.call(value) === "[object String]";
}

function isRecord(value: OpenApiValue | undefined): value is OpenApiObject {
  return value instanceof Object && !Array.isArray(value);
}
