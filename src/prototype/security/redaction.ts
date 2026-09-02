import { isCredentialFieldName, isCredentialHeaderName } from "./credentials.ts";

/** Removes credentials from data that may be persisted or rendered outside the live runtime. */
export function redactCredentials<T>(value: T): T {
  return redactValue(value) as T;
}

function redactValue(value: unknown, insideHeaders = false): unknown {
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([name, entry]) => [
      name,
      insideHeaders && isCredentialHeaderName(name)
        ? "[REDACTED]"
        : isCredentialFieldName(name)
          ? "[REDACTED]"
          : name.toLowerCase() === "body" && typeof entry === "string"
            ? redactCredentialBody(entry)
            : ["endpoint", "path", "target", "url"].includes(name.toLowerCase()) &&
                typeof entry === "string"
              ? redactCredentialUrl(entry)
              : redactValue(entry, name.toLowerCase() === "headers"),
    ]),
  );
}

function redactCredentialUrl(value: string): string {
  try {
    const absolute = /^[a-z][a-z\d+.-]*:/i.test(value);
    const url = new URL(value, "http://redaction.invalid");
    if (url.username || url.password) {
      url.username = "REDACTED";
      url.password = "REDACTED";
    }
    for (const name of new Set(url.searchParams.keys())) {
      if (isCredentialFieldName(name)) url.searchParams.set(name, "[REDACTED]");
    }
    return absolute ? url.href : `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "[REDACTED]";
  }
}

function redactCredentialBody(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    return parsed !== null && typeof parsed === "object"
      ? JSON.stringify(redactValue(parsed))
      : "[REDACTED]";
  } catch {
    // Unsupported body formats cannot be sanitized reliably enough for durable storage.
    return "[REDACTED]";
  }
}
