import { isCredentialFieldName, isCredentialHeaderName } from "./credentials.ts";

export function collectCredentialValues<T>(
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

export function isCredentialDataName(name: string): boolean {
  return (
    isCredentialFieldName(name) ||
    (name.toLowerCase().endsWith("s") && isCredentialFieldName(name.slice(0, -1)))
  );
}

export function isNumberOrBoolean<T>(value: T): boolean {
  return ["[object Number]", "[object Boolean]"].includes(Object.prototype.toString.call(value));
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

function isReference<T>(value: T): value is T & object {
  return Object(value) === value;
}

function isString<T>(value: T): boolean {
  return Object.prototype.toString.call(value) === "[object String]";
}

function isUrlFieldName(name: string): boolean {
  return ["endpoint", "path", "target", "url", "redirectlocation", "callbackurl"].includes(
    name.toLowerCase(),
  );
}
