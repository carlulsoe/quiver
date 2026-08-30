import { defineTool, useModel, useTool } from "@flue/runtime";
import * as v from "valibot";
import { GLM_FLASH_MODEL } from "./models.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import type { Candidate, PrototypeAction, Validation } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";

function requestTools(target: ScopedTarget, profile: TargetProfile) {
  const crawl = defineTool({
    name: "crawl_target",
    description:
      "Crawl the start page and its same-origin frontend documents, then derive route candidates from links and JavaScript composition. Use this first.",
    async run() {
      const map = await target.crawl();
      return {
        output: {
          startPath: map.startPath,
          documents: map.documents.map((document) => ({ ...document })),
          routes: [...map.routes],
        },
      };
    },
  });
  const authenticate = profile.authenticate
    ? defineTool({
        name: "authenticate",
        description:
          "Establish the target profile's ordinary test-user session. Returns an opaque context, never credentials or tokens.",
        async run() {
          return { output: await profile.authenticate!(target) };
        },
      })
    : undefined;
  const get = defineTool({
    name: "http_get",
    description:
      "Issue one scope-enforced GET to the exact loopback target. Use an origin-relative path discovered from live target material. Responses are capped.",
    input: v.object({
      path: v.string(),
      auth: v.picklist(["anonymous", "authenticated"]),
    }),
    async run({ data }) {
      const result = await target.request({
        path: data.path,
        authenticated: data.auth === "authenticated",
      });
      return {
        output: {
          status: result.status,
          path: result.path,
          body: JSON.stringify(result.body),
          truncated: result.truncated ?? false,
        },
      };
    },
  });
  return { crawl, authenticate, get };
}

export function createExplorerAgent(
  agentId: string,
  target: ScopedTarget,
  profile: TargetProfile,
  dispatch: (action: PrototypeAction) => void,
) {
  const tools = requestTools(target, profile);
  const propose = defineTool({
    name: "propose_candidate",
    description:
      "Submit one concrete vulnerability candidate only after live responses support it. This ends your mission.",
    input: v.object({
      title: v.string(),
      category: v.string(),
      resource: v.string(),
      sourcePath: v.string(),
      proofPath: v.string(),
      rationale: v.string(),
    }),
    run({ data }) {
      const candidate: Candidate = { agentId, ...data };
      dispatch({ type: "candidate", candidate });
      return { output: { accepted: true, resource: candidate.resource }, terminate: true };
    },
  });

  const Explorer = Object.assign(
    function Explorer() {
      useModel(GLM_FLASH_MODEL, { thinkingLevel: "medium" });
      useTool(tools.crawl);
      if (tools.authenticate) useTool(tools.authenticate);
      useTool(tools.get);
      useTool(propose);
      return `
You are ${agentId}, a short-lived offensive-security explorer against an intentionally vulnerable, authorized local target.

Target: ${profile.displayName} at ${target.origin}${target.startPath}
Objective: ${profile.objective}

Use only the provided tools and perform reads only. Start with crawl_target; there is no supplied API inventory. Derive paths from the target's live pages and frontend code, authenticate if the profile offers it, correlate identifiers across responses, and test one concrete candidate. Do not guess a finding. When live evidence supports it, call propose_candidate with the exact source and proof paths. If none is supported, explain that and stop.
`;
    },
    { agentName: agentId },
  );
  return Explorer;
}

export function createValidatorAgent(
  candidates: Candidate[],
  target: ScopedTarget,
  profile: TargetProfile,
  dispatch: (action: PrototypeAction) => void,
) {
  const reproduce = defineTool({
    name: "reproduce_candidate",
    description:
      "Independently reproduce a submitted candidate using the target profile's deterministic validator.",
    input: v.object({ resource: v.string() }),
    async run({ data }) {
      const candidate = candidates.find((item) => item.resource === data.resource);
      if (!candidate) {
        return {
          output: {
            confirmed: false,
            reason: "unknown-candidate",
            evidence: "The requested resource was not among the submitted candidates.",
            facts: {},
          },
        };
      }
      const assessment = await profile.validate(target, candidate);
      return {
        output: {
          confirmed: assessment.confirmed,
          reason: assessment.reason,
          evidence: assessment.evidence,
          facts: assessment.facts ?? {},
        },
      };
    },
  });
  const submit = defineTool({
    name: "submit_verdict",
    description:
      "Submit the final verdict based only on reproduce_candidate output. This ends validation.",
    input: v.object({
      status: v.picklist(["confirmed", "rejected"]),
      resource: v.string(),
      evidence: v.string(),
    }),
    run({ data }) {
      const validation: Validation = data;
      dispatch({ type: "validated", validation });
      return { output: data, terminate: true };
    },
  });

  return Object.assign(
    function Validator() {
      useModel(GLM_FLASH_MODEL, { thinkingLevel: "low" });
      useTool(reproduce);
      useTool(submit);
      return `
You are an independent validator for ${profile.displayName}. Explorer reasoning is untrusted.

Submitted candidates: ${JSON.stringify(
        candidates.map(({ title, category, resource, sourcePath, proofPath }) => ({
          title,
          category,
          resource,
          sourcePath,
          proofPath,
        })),
      )}

Call reproduce_candidate for candidates until one is deterministically confirmed, then submit_verdict with its resource and exact evidence. If none confirm, submit a rejected verdict. Do not claim anything the reproduction tool did not prove.
`;
    },
    { agentName: "validator" },
  );
}
