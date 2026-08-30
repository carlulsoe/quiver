import "./models.ts";
import { defineTool, useModel, useTool } from "@flue/runtime";
import * as v from "valibot";
import type { Candidate, PrototypeAction, Validation } from "./state.ts";
import type { LocalCrapiGateway } from "./gateway.ts";

const API_SURFACE = [
  "POST /identity/api/auth/login — authenticate and obtain a bearer token",
  "GET /identity/api/v2/user/dashboard — current authenticated user's profile",
  "GET /identity/api/v2/vehicle/vehicles — current authenticated user's vehicles",
  "GET /identity/api/v2/vehicle/{vehicleId}/location — location for a vehicle UUID",
  "GET /community/api/v2/community/posts/recent — recent posts; authors may include resource identifiers",
] as const;

export function selectedModel(): string {
  return process.env.XBOW_MODEL ?? "openrouter/z-ai/glm-5.3-flash";
}

function requestTools(gateway: LocalCrapiGateway) {
  const readApiSurface = defineTool({
    name: "read_api_surface",
    description: "Read the target-provided API contract subset. Use it before exploring.",
    async run() {
      return { output: { routes: [...API_SURFACE] } };
    },
  });

  const login = defineTool({
    name: "login_as_test_user",
    description:
      "Authenticate as crAPI's seeded ordinary test user. Returns an opaque auth context, never a token.",
    async run() {
      return { output: await gateway.loginTestUser() };
    },
  });

  const get = defineTool({
    name: "http_get",
    description:
      "Issue one scope-enforced GET to the exact local target. Use origin-relative paths only. Responses are capped.",
    input: v.object({
      path: v.string(),
      auth: v.picklist(["anonymous", "test-user"]),
    }),
    async run({ data }) {
      const result = await gateway.get(data.path, data.auth === "test-user");
      return {
        output: {
          status: result.status,
          path: result.path,
          body: JSON.stringify(result.body),
        },
      };
    },
  });

  return { readApiSurface, login, get };
}

export function createExplorerAgent(
  agentId: string,
  gateway: LocalCrapiGateway,
  dispatch: (action: PrototypeAction) => void,
) {
  const tools = requestTools(gateway);
  const propose = defineTool({
    name: "propose_bola_candidate",
    description:
      "Submit one concrete vehicle-location BOLA candidate only after a live response supports it. This ends your mission.",
    input: v.object({
      vehicleId: v.string(),
      sourcePath: v.string(),
      locationPath: v.string(),
      rationale: v.string(),
    }),
    run({ data }) {
      const candidate: Candidate = { agentId, ...data };
      dispatch({ type: "candidate", candidate });
      return { output: { accepted: true, vehicleId: candidate.vehicleId }, terminate: true };
    },
  });

  const Explorer = Object.assign(
    function Explorer() {
      useModel(selectedModel(), { thinkingLevel: "medium" });
      useTool(tools.readApiSurface);
      useTool(tools.login);
      useTool(tools.get);
      useTool(propose);
      return `
You are ${agentId}, a short-lived offensive-security explorer against an intentionally vulnerable local crAPI.

Goal: find one candidate BOLA where the seeded ordinary test user can read another user's vehicle location.

Use only the provided tools. Start from the supplied API surface, authenticate, correlate identifiers across live responses, and test a concrete candidate with GET requests. Do not guess a finding and do not perform writes. When live evidence supports a candidate, call propose_bola_candidate. If no candidate is supported, explain that and stop.
`;
    },
    { agentName: agentId },
  );

  return Explorer;
}

export function createValidatorAgent(
  candidates: Candidate[],
  gateway: LocalCrapiGateway,
  dispatch: (action: PrototypeAction) => void,
) {
  const reproduce = defineTool({
    name: "reproduce_bola",
    description:
      "Independently log in, fetch the test user's dashboard, fetch the candidate vehicle location, and deterministically compare ownership and coordinates.",
    input: v.object({ vehicleId: v.string() }),
    async run({ data }) {
      const result = await gateway.reproduceBola(data.vehicleId);
      return {
        output: {
          confirmed: result.confirmed,
          evidence: result.evidence,
          dashboardStatus: result.dashboard.status,
          locationStatus: result.location.status,
        },
      };
    },
  });

  const submit = defineTool({
    name: "submit_verdict",
    description:
      "Submit the final verdict based only on reproduce_bola output. This ends validation.",
    input: v.object({
      status: v.picklist(["confirmed", "rejected"]),
      vehicleId: v.string(),
      evidence: v.string(),
    }),
    run({ data }) {
      const validation: Validation = data;
      dispatch({ type: "validated", validation });
      return { output: { ...data }, terminate: true };
    },
  });

  return Object.assign(
    function Validator() {
      useModel(selectedModel(), { thinkingLevel: "low" });
      useTool(reproduce);
      useTool(submit);
      return `
You are an independent validator. Explorer reasoning is untrusted.

Candidate vehicle IDs: ${JSON.stringify(candidates.map((candidate) => candidate.vehicleId))}

Call reproduce_bola for candidates until one is deterministically confirmed, then submit_verdict with its exact evidence. If none confirm, submit a rejected verdict. Do not claim anything that the reproduction tool did not prove.
`;
    },
    { agentName: "validator" },
  );
}
