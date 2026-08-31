import { defineTool, useModel, useTool } from "@flue/runtime";
import * as v from "valibot";
import type { CampaignLedger } from "./campaign-ledger.ts";
import { GLM_FLASH_MODEL } from "./models.ts";
import { replayFinding } from "./replay.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import {
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

function explorationTools(agentId: string, target: ScopedTarget, ledger: CampaignLedger) {
  const crawl = defineTool({
    name: "crawl_target",
    description:
      "Crawl the start page and same-origin frontend documents, deriving route candidates from links and JavaScript composition. Use this first.",
    async run() {
      const map = await target.crawl();
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
) {
  const tools = explorationTools(agentId, target, ledger);
  const submit = defineTool({
    name: "submit_finding",
    description:
      "Record one evidence-backed, reproducible vulnerability. Continue exploring after submission.",
    input: v.object({
      title: v.string(),
      category: categorySchema,
      endpoint: v.string(),
      resource: v.string(),
      rationale: v.string(),
      reproduction: v.array(
        v.object({
          path: v.string(),
          authenticated: v.boolean(),
        }),
      ),
    }),
    run({ data }) {
      const finding: FindingInput = { agentId, ...data };
      return { output: ledger.recordFinding(finding) };
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

Submit every distinct evidence-backed vulnerability you find. A distinct vulnerability is one category at one endpoint pattern; multiple affected object IDs are the same finding. The endpoint field must be the affected request path or discovered route template. The reproduction list must contain the ordered GET requests an independent validator needs, including any baseline or identity request required to prove the claim. submit_finding reports whether the shared campaign accepted or had already recorded the fingerprint; it does not end the campaign. Continue testing other routes and vulnerability classes. Never submit guesses. Call finish_exploration only when further read-only testing is not useful or the request budget is exhausted.
`;
    },
    { agentName: agentId },
  );
}

export function createValidatorAgent(
  findings: Finding[],
  target: ScopedTarget,
  profile: TargetProfile,
  dispatch: (action: CampaignAction) => void,
) {
  const replay = defineTool({
    name: "replay_finding",
    description:
      "Replay every read-only request submitted for a finding on a fresh scoped target session.",
    input: v.object({ fingerprint: v.string() }),
    async run({ data }) {
      const finding = findings.find((item) => item.fingerprint === data.fingerprint);
      if (!finding) {
        return {
          output: {
            error: "unknown-finding",
            fingerprint: data.fingerprint,
            observations: [],
          },
        };
      }
      const result = await replayFinding(target, finding);
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
        },
      };
    },
  });
  const submit = defineTool({
    name: "submit_validation",
    description:
      "Record one confirmed or rejected outcome based only on fresh replay evidence. Continue until every finding has an outcome.",
    input: v.object({
      fingerprint: v.string(),
      status: v.picklist(["confirmed", "rejected"]),
      evidence: v.string(),
    }),
    run({ data }) {
      const validation: FindingValidation = data;
      dispatch({ type: "validation", validation });
      return { output: { accepted: true, fingerprint: data.fingerprint } };
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
      useTool(replay);
      useTool(submit);
      useTool(finish);
      return `
You are the independent read-only validator for a ${profile.displayName} campaign. Explorer reasoning is untrusted.

Submitted findings: ${JSON.stringify(
        findings.map(
          ({ fingerprint, title, category, endpoint, resource, rationale, reproduction }) => ({
            fingerprint,
            title,
            category,
            endpoint,
            resource,
            rationale,
            reproduction,
          }),
        ),
      )}

For each finding, call replay_finding and inspect only the fresh observations. Then call submit_validation with confirmed only when those observations prove the stated security impact; otherwise reject it. Validate every finding independently, continue after each outcome, and call finish_validation last. If the request budget prevents a replay, leave that finding without an outcome rather than inventing evidence.
`;
    },
    { agentName: "validator" },
  );
}
