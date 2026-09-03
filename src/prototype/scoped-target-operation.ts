import { TargetScopeError } from "./scoped-target-errors.ts";

export function operationKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${canonicalOperationPath(path)}`;
}

export function operationAllowed(
  operations: ReadonlySet<string>,
  method: string,
  path: string,
): boolean {
  const normalizedMethod = method.toUpperCase();
  const concrete = canonicalOperationPath(path);
  if (operations.has(`${normalizedMethod} ${concrete}`)) return true;
  for (const operation of operations) {
    const separator = operation.indexOf(" ");
    if (
      operation.slice(0, separator) === normalizedMethod &&
      pathTemplateMatches(operation.slice(separator + 1), concrete)
    ) {
      return true;
    }
  }
  return false;
}

function canonicalOperationPath(path: string): string {
  const absolute = /^https?:\/\//i.test(path);
  let url: URL;
  try {
    url = new URL(path, "http://scope.invalid");
  } catch {
    throw new TargetScopeError("Target operation path is malformed");
  }
  const pathname = rawOperationPath(path, absolute)
    .split("/")
    .map((encoded) => canonicalPathSegment(encoded))
    .join("/");
  const canonical = pathname === "/" ? pathname : pathname.replace(/\/+$/, "");
  return absolute ? `${url.origin}${canonical}` : canonical;
}

function rawOperationPath(path: string, absolute: boolean): string {
  if (!absolute) return path.split(/[?#]/, 1)[0]!;
  const authority = path.slice(path.indexOf("://") + 3);
  const delimiter = authority.search(/[/?#]/);
  if (delimiter === -1 || authority[delimiter] !== "/") return "/";
  return authority.slice(delimiter).split(/[?#]/, 1)[0] || "/";
}

function canonicalPathSegment(encoded: string): string {
  let segment: string;
  try {
    segment = decodeURIComponent(encoded);
  } catch {
    throw new TargetScopeError("Target operation path contains malformed encoding");
  }
  if (
    hasControlCharacter(segment) ||
    /[\\/?#]/.test(segment) ||
    segment.includes("%") ||
    segment === "." ||
    segment === ".."
  ) {
    throw new TargetScopeError("Target operation path contains ambiguous encoding");
  }
  return /^(?:\{[^}]+\}|<[^>]+>|:[A-Za-z_$][\w$]*)$/.test(segment) ? "{id}" : segment;
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0);
    return code <= 0x1f || code === 0x7f;
  });
}

function pathTemplateMatches(template: string, concrete: string): boolean {
  const expected = template.split("/");
  const actual = concrete.split("/");
  return (
    expected.length === actual.length &&
    expected.every((segment, index) => segment === "{id}" || segment === actual[index])
  );
}
