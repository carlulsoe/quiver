import { isCredentialFieldName, isCredentialHeaderName } from "./credentials.ts";

/** Removes credentials from data that may be persisted or rendered outside the live runtime. */
export function redactCredentials<T>(value: T): T {
  return redactCredentialsWithContext(value, value);
}

/** Redacts one value using credential material discovered in a wider trusted context. */
export function redactCredentialsWithContext<T, Context>(value: T, context: Context): T {
  const credentials = collectCredentialValues(context);
  return redactValue(
    value,
    false,
    [...credentials].sort((left, right) => right.length - left.length),
  ) as T;
}

/** Redacts a response-derived value while its JSON Pointer provenance is still available. */
export function redactCredentialPathValue<T>(pointer: string, value: T): T | string {
  const sensitive = pointer
    .split("/")
    .slice(1)
    .map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"))
    .some(isCredentialDataName);
  return sensitive ? "[REDACTED]" : redactCredentials(value);
}

function redactValue<T>(value: T, insideHeaders: boolean, credentials: readonly string[]): T {
  if (Array.isArray(value)) return value.map((item) => redactValue(item, false, credentials)) as T;
  if (!isReference(value)) {
    if (isString(value)) return redactKnownCredentials(String(value), credentials) as T;
    if (isNumberOrBoolean(value) && credentials.includes(String(value))) return "[REDACTED]" as T;
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).map(([name, entry]) => [
      name,
      insideHeaders && isCredentialHeaderName(name)
        ? "[REDACTED]"
        : name === "passed"
          ? entry
          : isCredentialDataName(name)
            ? "[REDACTED]"
            : name.toLowerCase() === "body" && isString(entry)
              ? redactCredentialBody(String(entry), credentials)
              : isUrlFieldName(name) && isString(entry)
                ? redactKnownCredentials(redactCredentialUrl(String(entry)), credentials)
                : redactValue(entry, name.toLowerCase() === "headers", credentials),
    ]),
  ) as T;
}

function collectCredentialValues<T>(
  value: T,
  insideHeaders = false,
  found = new Set<string>(),
): Set<string> {
  if (Array.isArray(value)) {
    for (const item of value) collectCredentialValues(item, false, found);
    return found;
  }
  if (!isReference(value)) return found;
  for (const [name, entry] of Object.entries(value)) {
    if ((insideHeaders && isCredentialHeaderName(name)) || isCredentialDataName(name))
      collectCredentialEntry(entry, found);
    else if (name.toLowerCase() === "body" && isString(entry))
      collectCredentialBody(String(entry), found);
    else if (isUrlFieldName(name) && isString(entry)) collectCredentialUrl(String(entry), found);
    collectCredentialValues(entry, name.toLowerCase() === "headers", found);
  }
  return found;
}

function collectCredentialEntry<T>(value: T, found: Set<string>): void {
  if (isString(value)) {
    const credential = String(value);
    if (credential.length > 0 && credential !== "[REDACTED]") found.add(credential);
    const authorizationValue = credential.match(/^(?:basic|bearer)\s+(.+)$/i)?.[1];
    if (authorizationValue) found.add(authorizationValue);
    return;
  }
  if (isNumberOrBoolean(value)) {
    found.add(String(value));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectCredentialEntry(item, found);
    return;
  }
  if (isReference(value))
    for (const entry of Object.values(value)) collectCredentialEntry(entry, found);
}

function collectCredentialBody(body: string, found: Set<string>): void {
  try {
    collectCredentialValues(JSON.parse(body), false, found);
    return;
  } catch {
    // Try form-encoded request bodies after JSON.
  }
  const parameters = new URLSearchParams(body);
  for (const [name, value] of parameters)
    if (isCredentialDataName(name)) collectCredentialEntry(value, found);
}

function collectCredentialUrl(value: string, found: Set<string>): void {
  try {
    const url = new URL(value, "http://redaction.invalid");
    collectCredentialEntry(url.username, found);
    collectCredentialEntry(url.password, found);
    for (const [name, entry] of url.searchParams)
      if (isCredentialDataName(name)) collectCredentialEntry(entry, found);
  } catch {
    // Malformed URL-like fields are fully redacted during the rendering pass.
  }
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

function isNumberOrBoolean<T>(value: T): boolean {
  return ["[object Number]", "[object Boolean]"].includes(Object.prototype.toString.call(value));
}

function isUrlFieldName(name: string): boolean {
  return ["endpoint", "path", "target", "url", "redirectlocation", "callbackurl"].includes(
    name.toLowerCase(),
  );
}

function isCredentialDataName(name: string): boolean {
  return (
    isCredentialFieldName(name) ||
    (name.toLowerCase().endsWith("s") && isCredentialFieldName(name.slice(0, -1)))
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
      ? JSON.stringify(redactValue(parsed, false, credentials))
      : "[REDACTED]";
  } catch {
    // Unsupported body formats cannot be sanitized reliably enough for durable storage.
    return "[REDACTED]";
  }
}
