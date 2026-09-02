import * as v from "valibot";

export const categorySchema = v.picklist([
  "broken-object-authorization",
  "broken-function-authorization",
  "authentication-bypass",
  "excessive-data-exposure",
  "sensitive-data-exposure",
  "cross-site-scripting",
  "sql-injection",
  "command-injection",
  "server-side-request-forgery",
  "path-traversal",
  "open-redirect",
  "cross-site-request-forgery",
  "business-logic",
  "security-misconfiguration",
  "other",
]);
export const indexSchema = v.pipe(v.number(), v.integer(), v.minValue(0));
export const methodSchema = v.picklist([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);
export const specialtySchema = v.picklist([
  "authorization",
  "authentication",
  "data-exposure",
  "request-semantics",
]);
export const impactLevelSchema = v.picklist(["observation", "bounded", "state-change"]);
export const jsonPointerSchema = v.pipe(
  v.string(),
  v.regex(/^(?:\/[^/]*)*$/, "Use an RFC 6901 JSON pointer such as /user/email"),
);
