import { defineTool, useModel, useResponseFinish, useTool } from "@flue/runtime";
import * as v from "valibot";
import type { CampaignLedger } from "./campaign-ledger.ts";
import { GLM_FLASH_MODEL } from "./models.ts";
import { evaluateProof } from "./proof.ts";
import { replayFinding } from "./replay.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import {
  fingerprintFinding,
  type CampaignAction,
  type Finding,
  type FindingInput,
  type FindingValidation,
} from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";

const categorySchema = v.picklist([
  "broken-object-authorization",
  "broken-function-authorization",
  "excessive-data-exposure",
  "sensitive-data-exposure",
  "security-misconfiguration",
  "other",
]);
const indexSchema = v.pipe(v.number(), v.integer(), v.minValue(0));
const jsonPointerSchema = v.pipe(
  v.string(),
  v.regex(/^(?:\/[^/]*)*$/, "Use an RFC 6901 JSON pointer such as /user/email"),
);
const evidenceSelectorSchema = v.object({
  requestIndex: indexSchema,
  jsonPointer: jsonPointerSchema,
});
const proofSchema = v.variant("type", [
  v.object({
    type: v.literal("cross-principal-access"),
    actor: evidenceSelectorSchema,
    resourceOwner: evidenceSelectorSchema,
    accessRequestIndex: indexSchema,
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
]);

function useUsageMetadata() {
  useResponseFinish(({ response }) => ({ quiverUsage: response.usage }));
}

function explorationTools(
  agentId: string,
  target: ScopedTarget,
  ledger: CampaignLedger,
  dispatch: (action: CampaignAction) => void,
) {
  const crawl = defineTool({
    name: "crawl_target",
    description:
      "Crawl the start page and same-origin frontend documents, deriving route candidates from links and JavaScript composition. Use this first.",
    async run() {
      const map = await target.crawl();
      dispatch({ type: "routes-discovered", routes: map.routeDetails.map(({ path }) => path) });
      return {
        output: {
          startPath: map.startPath,
          documents: map.documents.map((document) => ({ ...document })),
          routes: [...map.routes],
          routeDetails: map.routeDetails.map((detail) => ({
            path: detail.path,
            sources: [...detail.sources],
            getCallSites: detail.getCallSites.map((callSite) => ({ ...callSite })),
            identifierSources: detail.identifierSources.map((source) => ({ ...source })),
          })),
        },
      };
    },
  });
  const get = defineTool({
    name: "http_get",
    description:
      "Issue one scope-enforced GET to a discovered origin-relative path. Responses are capped.",
    input: v.object({
      path: v.string(),
      auth: v.picklist(["anonymous", "authenticated"]),
    }),
    async run({ data }) {
      const authenticated = data.auth === "authenticated";
      const { observation: result, reused } = await ledger.request(
        { agentId, path: data.path, authenticated },
        () => target.request({ path: data.path, authenticated }),
      );
      return {
        output: {
          status: result.status,
          path: result.path,
          body: JSON.stringify(result.body),
          truncated: result.truncated ?? false,
          reused,
        },
      };
    },
  });
  const review = defineTool({
    name: "review_campaign",
    description:
      "Read the shared ledger of exact requests already tested and distinct findings already submitted by all explorers.",
    run() {
      const snapshot = ledger.snapshot();
      return {
        output: {
          testedRequests: snapshot.testedRequests.map((request) => ({ ...request })),
          findings: snapshot.findings.map((finding) => ({ ...finding })),
        },
      };
    },
  });
  return { crawl, get, review };
}

export function createExplorerAgent(
  agentId: string,
  focus: string,
  target: ScopedTarget,
  profile: TargetProfile,
  ledger: CampaignLedger,
  dispatch: (action: CampaignAction) => void,
) {
  const tools = explorationTools(agentId, target, ledger, dispatch);
  const submit = defineTool({
    name: "submit_finding",
    description:
      "Record one evidence-backed, reproducible vulnerability. Continue exploring after submission.",
    input: v.object({
      title: v.string(),
      category: categorySchema,
      severity: v.picklist(["low", "medium", "high", "critical"]),
      cwe: v.string(),
      endpoint: v.string(),
      resource: v.string(),
      rationale: v.string(),
      impact: v.string(),
      mitigation: v.string(),
      reproduction: v.array(
        v.object({
          path: v.string(),
          authenticated: v.boolean(),
        }),
      ),
      proof: proofSchema,
    }),
    run({ data }) {
      const finding: FindingInput = { agentId, ...data };
      const fingerprint = fingerprintFinding(finding);
      const observations = ledger.observationsFor(finding.reproduction);
      if (!observations) {
        return {
          output: {
            accepted: false,
            fingerprint,
            error: "Every reproduction request must have a completed matching http_get observation",
            deterministicProof: null,
          },
        };
      }
      const proof = evaluateProof(finding, observations);
      if (!proof.passed) {
        return {
          output: {
            accepted: false,
            fingerprint,
            error: "The deterministic proof does not pass against exploration observations",
            deterministicProof: proofOutput(proof),
          },
        };
      }
      const recorded = ledger.recordFinding(finding);
      return {
        output: {
          ...recorded,
          error: null,
          deterministicProof: proofOutput(proof),
        },
      };
    },
  });
  const finish = defineTool({
    name: "finish_exploration",
    description:
      "Finish only after testing the useful read-only attack surface or exhausting the available request budget.",
    run() {
      return { output: { finished: true }, terminate: true };
    },
  });

  return Object.assign(
    function Explorer() {
      useModel(GLM_FLASH_MODEL, { thinkingLevel: "medium" });
      useUsageMetadata();
      useTool(tools.crawl);
      useTool(tools.get);
      useTool(tools.review);
      useTool(submit);
      useTool(finish);
      return `
You are ${agentId}, a read-only security explorer in a bounded campaign against an intentionally vulnerable, authorized local target.

Target: ${profile.displayName} at ${target.origin}${target.startPath}
Campaign objective: ${profile.objective}
Your complementary campaign focus: ${focus}

Start with crawl_target, then review_campaign; no API inventory is supplied. Use only the provided tools. The target profile has already prepared any available ordinary-user session. Use routeDetails to prioritize observed GET call sites, likely authentication requirements, and identifier-source relationships. Derive paths from live target material, correlate identifiers and identities across anonymous and authenticated responses, and test concrete hypotheses with GET requests. Prioritize your assigned focus before broadening into other read-only vulnerability classes. Consult review_campaign again only when choosing between hypotheses that another explorer may already have tested. http_get safely reuses an existing exact observation when another explorer has already made the same authenticated or anonymous request.

Submit every distinct evidence-backed vulnerability you find. A distinct vulnerability is one category at one endpoint pattern; multiple affected object IDs are the same finding. Include severity, a precise CWE identifier, impact, and actionable mitigation. The endpoint field must be the affected request path or discovered route template.

The reproduction list must contain the ordered GET requests an independent validator needs. Every finding must also declare a machine-checkable proof predicate using zero-based reproduction request indexes and RFC 6901 JSON pointers into parsed response bodies:
- cross-principal-access: identify the authenticated actor and the accessed resource owner in replay responses; they must differ, the access response must succeed, and each evidence pointer must exist in that access response (use this for concrete impact or canary fields).
- unauthenticated-success: identify an anonymous request whose successful response contains each declared evidence field.
- cross-principal-data-exposure: identify the authenticated actor and a different subject whose fields appear in the successful response, plus every concrete exposed field.
- internal-field-exposure: identify a successful response and implementation-only fields whose presence alone violates the response contract. Use this only for unmistakable internal/debug/configuration properties—not normal fields from the caller's own resource. Owner access to their own identifiers, credentials, location, or profile data is not evidence of excessive exposure.

Choose a predicate compatible with the category and point only to values you observed. The affected endpoint must match at least one reproduction request. submit_finding first runs the predicate against the shared exploration observations; if a selector or condition fails, inspect its deterministicProof checks, correct the finding, and resubmit. The same predicate must later pass against a fresh replay. The deterministic predicate, not the validation model's opinion, decides confirmation. submit_finding reports whether the shared campaign accepted or had already recorded the fingerprint; it does not end the campaign. Continue testing other routes and vulnerability classes. A showcase-strength campaign should support at least three distinct machine-proven findings when the target and budget permit; if the shared ledger has fewer, keep testing unexamined actionable routes. Never submit guesses. Call finish_exploration only when further read-only testing is not useful or the request budget is exhausted.
`;
    },
    { agentName: agentId },
  );
}

export function createValidatorAgent(
  getFindings: () => Finding[],
  getTarget: () => ScopedTarget,
  profile: TargetProfile,
  dispatch: (action: CampaignAction) => void,
) {
  const replays = new Map<string, Awaited<ReturnType<typeof replayFinding>>>();
  const replay = defineTool({
    name: "replay_finding",
    description:
      "Replay every read-only request submitted for a finding on a fresh scoped target session.",
    input: v.object({ fingerprint: v.string() }),
    async run({ data }) {
      const findings = getFindings();
      const finding = findings.find((item) => item.fingerprint === data.fingerprint);
      if (!finding) {
        return {
          output: {
            error: "unknown-finding",
            fingerprint: data.fingerprint,
            observations: [],
            deterministicProof: null,
          },
        };
      }
      const result = await replayFinding(getTarget(), finding);
      replays.set(finding.fingerprint, result);
      const proof = evaluateProof(finding, result.observations);
      return {
        output: {
          error: null,
          fingerprint: result.fingerprint,
          observations: result.observations.map((observation) => ({
            status: observation.status,
            path: observation.path,
            body: JSON.stringify(observation.body),
            truncated: observation.truncated,
          })),
          deterministicProof: proofOutput(proof),
        },
      };
    },
  });
  const submit = defineTool({
    name: "submit_validation",
    description:
      "Record an informational review after replay. Quiver computes the authoritative outcome from the declared proof predicate.",
    input: v.object({
      fingerprint: v.string(),
      assessment: v.picklist(["supported", "unsupported"]),
      evidence: v.string(),
    }),
    run({ data }) {
      const finding = getFindings().find((item) => item.fingerprint === data.fingerprint);
      const replayResult = replays.get(data.fingerprint);
      if (!finding || !replayResult) {
        return {
          output: {
            accepted: false,
            fingerprint: data.fingerprint,
            error: finding ? "replay-required" : "unknown-finding",
            status: null,
            deterministicProof: null,
          },
        };
      }
      const proof = evaluateProof(finding, replayResult.observations);
      const validation: FindingValidation = {
        fingerprint: data.fingerprint,
        status: proof.passed ? "confirmed" : "rejected",
        evidence: proof.summary,
        proof,
        observations: replayResult.observations,
        reviewer: { assessment: data.assessment, evidence: data.evidence },
      };
      dispatch({ type: "validation", validation });
      return {
        output: {
          accepted: true,
          fingerprint: data.fingerprint,
          error: null,
          status: validation.status,
          deterministicProof: proofOutput(proof),
        },
      };
    },
  });
  const finish = defineTool({
    name: "finish_validation",
    description:
      "Finish after submitting an outcome for every finding that the budget permits replaying.",
    run() {
      return { output: { finished: true }, terminate: true };
    },
  });

  return Object.assign(
    function Validator() {
      useModel(GLM_FLASH_MODEL, { thinkingLevel: "medium" });
      useUsageMetadata();
      useTool(replay);
      useTool(submit);
      useTool(finish);
      return `
You are the independent read-only validator for a ${profile.displayName} campaign. Explorer reasoning is untrusted.

Submitted findings: ${JSON.stringify(
        getFindings().map(
          ({
            fingerprint,
            title,
            category,
            endpoint,
            resource,
            rationale,
            reproduction,
            proof,
          }) => ({
            fingerprint,
            title,
            category,
            endpoint,
            resource,
            rationale,
            reproduction,
            proof,
          }),
        ),
      )}

For each finding, call replay_finding and inspect only the fresh observations and deterministicProof checks. Then call submit_validation with your informational supported/unsupported assessment and a concise explanation. You do not decide confirmation: submit_validation records the code-owned predicate result as the authoritative outcome. Review every finding independently, continue after each outcome, and call finish_validation last. If the request budget prevents a replay, leave that finding without an outcome rather than inventing evidence.
`;
    },
    { agentName: "validator" },
  );
}

function proofOutput(proof: ReturnType<typeof evaluateProof>) {
  return {
    predicate: proof.predicate,
    passed: proof.passed,
    summary: proof.summary,
    checks: proof.checks.map((item) => ({
      description: item.description,
      passed: item.passed,
      actual: item.actual === undefined ? null : JSON.stringify(item.actual),
    })),
  };
}
