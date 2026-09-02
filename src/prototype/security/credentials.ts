const CREDENTIAL_MARKERS = new Set([
  "auth",
  "authentication",
  "authorization",
  "cookie",
  "credential",
  "password",
  "passwd",
  "passphrase",
  "secret",
  "session",
  "signature",
  "token",
]);

const KEY_QUALIFIERS = new Set(["access", "api", "client", "private", "security"]);

/** Classifies request headers capable of selecting or replacing an authenticated identity. */
export function isCredentialHeaderName(name: string): boolean {
  const parts = nameParts(name);
  const compact = parts.join("");
  return (
    parts.some((part) => CREDENTIAL_MARKERS.has(part)) ||
    [...CREDENTIAL_MARKERS].some((marker) => compact.endsWith(marker)) ||
    ((parts.includes("key") || compact.endsWith("key")) &&
      [...KEY_QUALIFIERS].some((qualifier) => compact.includes(`${qualifier}key`)))
  );
}

/** Classifies persisted field names whose values must not appear in reports or discovery data. */
export function isCredentialFieldName(name: string): boolean {
  const parts = nameParts(name);
  return (
    isCredentialHeaderName(name) ||
    parts.some((part) => ["key", "otp", "pin"].includes(part)) ||
    ((parts.includes("verification") || parts.includes("mfa")) && parts.includes("code"))
  );
}

export function containsCredentialHeader(
  headers: Readonly<Record<string, string>> | undefined,
): boolean {
  return Object.keys(headers ?? {}).some(isCredentialHeaderName);
}

function nameParts(name: string): string[] {
  return name
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}
