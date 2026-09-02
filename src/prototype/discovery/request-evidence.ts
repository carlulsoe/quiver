import type { Request } from "playwright-core";
import type { AttackSurfaceGraphqlOperation, AttackSurfaceRequestBody } from "../attack-surface.ts";
import { isCredentialFieldName } from "../security/credentials.ts";
import { discoverGraphqlOperations } from "./graphql.ts";

export function observeRequestBody(request: Request): AttackSurfaceRequestBody | undefined {
  const postData = request.postData();
  if (postData === null) return undefined;
  const contentType = request.headers()["content-type"]?.split(";", 1)[0]?.trim() ?? "";
  if (contentType === "application/json" || contentType.endsWith("+json")) {
    try {
      return { contentType, source: "browser", example: safeExample(JSON.parse(postData)) };
    } catch {
      return { contentType, source: "browser" };
    }
  }
  if (contentType === "application/x-www-form-urlencoded") {
    const values = Object.fromEntries(new URLSearchParams(postData));
    return {
      contentType,
      source: "browser",
      example: safeExample(values),
      fields: Object.keys(values),
    };
  }
  if (contentType === "multipart/form-data") return observeMultipart(postData);
  return { contentType: contentType || "application/octet-stream", source: "browser" };
}

export function discoverGraphqlOperationsFromRequest(
  request: Request,
): AttackSurfaceGraphqlOperation[] {
  const queries = new URL(request.url()).searchParams.getAll("query");
  const postData = request.postData();
  if (postData) {
    const contentType = request.headers()["content-type"] ?? "";
    if (contentType.includes("json")) {
      try {
        const body: unknown = JSON.parse(postData);
        for (const entry of Array.isArray(body) ? body : [body]) {
          if (isRecord(entry) && typeof entry.query === "string") queries.push(entry.query);
        }
      } catch {
        // The malformed body remains visible as body-format metadata.
      }
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      const query = new URLSearchParams(postData).get("query");
      if (query) queries.push(query);
    } else if (contentType.includes("multipart/form-data")) {
      for (const match of postData.matchAll(/\r?\n\r?\n({[\s\S]*?})\r?\n--/g)) {
        try {
          const body: unknown = JSON.parse(match[1]!);
          if (isRecord(body) && typeof body.query === "string") queries.push(body.query);
        } catch {
          // Ignore file data and unrelated multipart fields.
        }
      }
    }
  }
  return uniqueJson(queries.flatMap(discoverGraphqlOperations));
}

export function safeExample(value: unknown): unknown {
  try {
    const json = JSON.stringify(value);
    if (json === undefined) return undefined;
    if (json.length > 8_000) return "[example truncated]";
    return redactSensitiveExample(JSON.parse(json) as unknown);
  } catch {
    return undefined;
  }
}

function observeMultipart(postData: string): AttackSurfaceRequestBody {
  const fields: string[] = [];
  const files: NonNullable<AttackSurfaceRequestBody["files"]> = [];
  for (const match of postData.matchAll(/content-disposition:\s*form-data;([^\r\n]*)/gi)) {
    const parameters = match[1] ?? "";
    const name = /\bname="([^"]+)"/i.exec(parameters)?.[1];
    if (!name) continue;
    const fileName = /\bfilename="([^"]*)"/i.exec(parameters)?.[1];
    if (fileName !== undefined) files.push({ field: name, fileName });
    else fields.push(name);
  }
  return {
    contentType: "multipart/form-data",
    source: "browser",
    fields: [...new Set(fields)],
    files: uniqueJson(files),
  };
}

function redactSensitiveExample(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSensitiveExample);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, child]) => [
      key,
      isCredentialFieldName(key) ? "[redacted]" : redactSensitiveExample(child),
    ]),
  );
}

function uniqueJson<T>(values: readonly T[]): T[] {
  return values.filter(
    (value, index) =>
      values.findIndex((candidate) => JSON.stringify(candidate) === JSON.stringify(value)) ===
      index,
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
