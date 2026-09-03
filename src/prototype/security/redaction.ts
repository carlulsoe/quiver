import { isCredentialHeaderName } from "./credentials.ts";
import {
  collectCredentialValues,
  isCredentialDataName,
  isNumberOrBoolean,
} from "./redaction-context.ts";

/** Removes credentials from data that may be persisted or rendered outside the live runtime. */
export function redactCredentials<T>(value: T): T {
  return redactCredentialsWithContext(value, value);
}

/** Redacts one value using credential material discovered in a wider trusted context. */
export function redactCredentialsWithContext<T, Context>(value: T, context: Context): T {
  return redactWithContext(value, context, "untrusted");
}

/** Redacts a typed report or proof while treating only raw payload containers as untrusted. */
export function redactStructuredCredentials<T>(value: T): T {
  return redactStructuredCredentialsWithContext(value, value);
}

/** Redacts a typed report or proof using credential material from a wider trusted context. */
export function redactStructuredCredentialsWithContext<T, Context>(value: T, context: Context): T {
  return redactWithContext(value, context, "structured");
}

type ScalarProvenance = "structured" | "untrusted";

function redactWithContext<T, Context>(
  value: T,
  context: Context,
  provenance: ScalarProvenance,
): T {
  const credentials = collectCredentialValues(context);
  return redactValue(
    value,
    false,
    [...credentials].sort((left, right) => right.length - left.length),
    provenance,
  ) as T;
}

/** Redacts a response-derived value while its JSON Pointer provenance is still available. */
export function redactCredentialPathValue<T, Context = T>(
  pointer: string,
  value: T,
  context?: Context,
): T | string {
  const sensitive = pointer
    .split("/")
    .slice(1)
    .map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"))
    .some(isCredentialDataName);
  return sensitive
    ? "[REDACTED]"
    : redactCredentialsWithContext(value, context === undefined ? value : context);
}

function redactValue<T>(
  value: T,
  insideHeaders: boolean,
  credentials: readonly string[],
  provenance: ScalarProvenance,
): T {
  if (Array.isArray(value))
    return value.map((item) => redactValue(item, false, credentials, provenance)) as T;
  if (!isReference(value)) {
    if (isString(value)) return redactKnownCredentials(String(value), credentials) as T;
    if (
      provenance === "untrusted" &&
      isNumberOrBoolean(value) &&
      credentials.includes(String(value))
    )
      return "[REDACTED]" as T;
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).map(([name, entry]) => [
      name,
      insideHeaders && isCredentialHeaderName(name)
        ? "[REDACTED]"
        : isCredentialDataName(name)
          ? "[REDACTED]"
          : name.toLowerCase() === "body" && isString(entry)
            ? redactCredentialBody(String(entry), credentials)
            : isUrlFieldName(name) && isString(entry)
              ? redactKnownCredentials(redactCredentialUrl(String(entry)), credentials)
              : redactValue(
                  entry,
                  name.toLowerCase() === "headers",
                  credentials,
                  provenance === "structured" && isUntrustedPayloadField(name)
                    ? "untrusted"
                    : provenance,
                ),
    ]),
  ) as T;
}

function redactKnownCredentials(value: string, credentials: readonly string[]): string {
  return credentials.reduce(
    (redacted, credential) => redactKnownCredential(redacted, credential),
    value,
  );
}

function redactKnownCredential(value: string, credential: string): string {
  if (credential.length >= 4) return value.replaceAll(credential, "[REDACTED]");
  if (value === credential) return "[REDACTED]";
  const escaped = credential.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return value.replace(
    new RegExp(`(^|[^\\p{L}\\p{N}])${escaped}(?=$|[^\\p{L}\\p{N}])`, "gu"),
    "$1[REDACTED]",
  );
}

function isReference<T>(value: T): value is T & object {
  return Object(value) === value;
}

function isString<T>(value: T) {
  return Object.prototype.toString.call(value) === "[object String]";
}

function isUrlFieldName(name: string): boolean {
  return ["endpoint", "path", "target", "url", "redirectlocation", "callbackurl"].includes(
    name.toLowerCase(),
  );
}

function isUntrustedPayloadField(name: string): boolean {
  return ["actual", "body", "input", "output"].includes(name.toLowerCase());
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
      if (isCredentialDataName(name)) url.searchParams.set(name, "[REDACTED]");
    }
    return absolute ? url.href : `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "[REDACTED]";
  }
}

function redactCredentialBody(body: string, credentials: readonly string[]): string {
  try {
    const parsed = JSON.parse(body);
    return parsed instanceof Object
      ? JSON.stringify(redactValue(parsed, false, credentials, "untrusted"))
      : "[REDACTED]";
  } catch {
    // Unsupported body formats cannot be sanitized reliably enough for durable storage.
    return "[REDACTED]";
  }
}
