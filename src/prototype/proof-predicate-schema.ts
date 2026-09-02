import * as v from "valibot";

const indexSchema = v.pipe(v.number(), v.integer(), v.minValue(0));
const jsonPointerSchema = v.pipe(
  v.string(),
  v.regex(/^(?:\/[^/]*)*$/, "Use an RFC 6901 JSON pointer such as /user/email"),
);
const evidenceSelectorSchema = v.object({
  requestIndex: indexSchema,
  jsonPointer: jsonPointerSchema,
});
const challengeMutationSchema = v.object({
  location: v.picklist(["query", "json-body"]),
  parameter: v.pipe(v.string(), v.minLength(1)),
  template: v.pipe(v.string(), v.includes("{{challenge}}")),
});
const browserChallengeMutationSchema = v.object({
  location: v.picklist(["query", "json-body", "fragment"]),
  parameter: v.pipe(v.string(), v.minLength(1)),
  template: v.pipe(v.string(), v.includes("{{challenge}}")),
});

/** Runtime schema kept with the engine so proof-pack additions do not edit agent orchestration. */
export const proofPredicateSchema = v.variant("type", [
  v.object({
    type: v.literal("cross-principal-access"),
    actor: evidenceSelectorSchema,
    resourceOwner: evidenceSelectorSchema,
    accessRequestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("authentication-bypass"),
    authenticatedRequestIndex: indexSchema,
    anonymousRequestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("role-privilege-differential"),
    authorizedRequestIndex: indexSchema,
    lessPrivilegedRequestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("unauthenticated-success"),
    requestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("cross-principal-data-exposure"),
    actor: evidenceSelectorSchema,
    exposedSubject: evidenceSelectorSchema,
    responseRequestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("internal-field-exposure"),
    requestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("canary-retrieval"),
    policyId: v.string(),
    requestIndex: indexSchema,
    jsonPointer: jsonPointerSchema,
  }),
  v.object({
    type: v.literal("file-content-retrieval"),
    policyId: v.string(),
    requestIndex: indexSchema,
  }),
  v.object({
    type: v.literal("redirect-destination"),
    policyId: v.string(),
    requestIndex: indexSchema,
    destination: v.string(),
  }),
  v.object({
    type: v.literal("sql-semantic-differential"),
    policyId: v.string(),
    controlRequestIndex: indexSchema,
    probeRequestIndex: indexSchema,
  }),
  v.object({
    type: v.literal("command-execution-challenge"),
    policyId: v.string(),
    requestIndex: indexSchema,
    challenge: v.pipe(v.number(), v.integer(), v.minValue(1)),
  }),
  v.object({
    type: v.literal("state-transition"),
    policyId: v.string(),
    transitionRequestIndex: indexSchema,
    beforeRequestIndex: indexSchema,
    afterRequestIndex: indexSchema,
  }),
  v.object({
    type: v.literal("browser-visible-effect"),
    policyId: v.string(),
    probeId: v.string(),
    marker: v.string(),
    requestIndex: indexSchema,
    pagePath: v.string(),
    kind: v.literal("dialog"),
    challenge: browserChallengeMutationSchema,
    pageActorId: v.string(),
    pageChallenge: v.optional(browserChallengeMutationSchema),
    collectorRequestBudget: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(20)),
  }),
  v.object({
    type: v.literal("browser-state-transition"),
    policyId: v.string(),
    beforeRequestIndex: indexSchema,
    afterRequestIndex: indexSchema,
    pageActorId: v.string(),
    collectorRequestBudget: v.pipe(v.number(), v.integer(), v.minValue(2), v.maxValue(20)),
  }),
  v.object({
    type: v.literal("oast-callback"),
    policyId: v.string(),
    probeId: v.string(),
    token: v.string(),
    requestIndex: indexSchema,
    callbackUrl: v.string(),
    challenge: challengeMutationSchema,
  }),
]);
