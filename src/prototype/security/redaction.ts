import { isCredentialFieldName, isCredentialHeaderName } from "./credentials.ts";

/** Removes credentials from data that may be persisted or rendered outside the live runtime. */
export function redactCredentials<T>(value: T): T {
  return redactValue(value) as T;
}

function redactValue<T>(value: T, insideHeaders = false): T {
  if (Array.isArray(value)) return value.map((item) => redactValue(item)) as T;
  if (!isReference(value)) return value;
  return Object.fromEntries(
    Object.entries(value).map(([name, entry]) => [
      name,
      insideHeaders && isCredentialHeaderName(name)
        ? "[REDACTED]"
        : isCredentialFieldName(name)
          ? "[REDACTED]"
          : name.toLowerCase() === "body" && isString(entry)
            ? redactCredentialBody(String(entry))
            : ["endpoint", "path", "target", "url"].includes(name.toLowerCase()) && isString(entry)
              ? redactCredentialUrl(String(entry))
              : redactValue(entry, name.toLowerCase() === "headers"),
    ]),
  ) as T;
}

function isReference<T>(value: T): value is T & object {
  return Object(value) === value;
}

function isString<T>(value: T) {
  return Object.prototype.toString.call(value) === "[object String]";
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
    const parsed = JSON.parse(body);
    return parsed instanceof Object ? JSON.stringify(redactValue(parsed)) : "[REDACTED]";
  } catch {
    // Unsupported body formats cannot be sanitized reliably enough for durable storage.
    return "[REDACTED]";
  }
}
