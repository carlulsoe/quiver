import type { FindingCategory, ProofPredicate } from "./state.ts";

export const compatiblePredicates = {
  "broken-object-authorization": ["cross-principal-access"],
  "broken-function-authorization": ["cross-principal-access", "role-privilege-differential"],
  "authentication-bypass": ["authentication-bypass"],
  "excessive-data-exposure": [
    "cross-principal-data-exposure",
    "internal-field-exposure",
    "canary-retrieval",
  ],
  "sensitive-data-exposure": [
    "cross-principal-data-exposure",
    "internal-field-exposure",
    "canary-retrieval",
  ],
  "cross-site-scripting": ["browser-visible-effect"],
  "sql-injection": ["sql-semantic-differential"],
  "command-injection": ["command-execution-challenge"],
  "server-side-request-forgery": ["oast-callback"],
  "path-traversal": ["canary-retrieval", "file-content-retrieval"],
  "open-redirect": ["redirect-destination"],
  "cross-site-request-forgery": ["browser-state-transition"],
  "business-logic": ["state-transition", "role-privilege-differential"],
  "security-misconfiguration": ["unauthenticated-success"],
  other: [],
} satisfies Record<FindingCategory, readonly ProofPredicate["type"][]>;
