import { defineTool } from "@flue/runtime";
import type { AdaptiveCoordinator } from "./adaptive-coordinator.ts";
import type { CampaignLedger } from "./campaign-ledger.ts";
import { methodSchema } from "./agent-schemas.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { CampaignAction } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";
import { NON_REST_AGENT_TOOLS, type BoundedToolAdapters } from "./tool-adapters.ts";
import type { VerificationEngine } from "./verification.ts";
import * as v from "valibot";

type ToolJson = string | number | boolean | null | ToolJson[] | { [key: string]: ToolJson };

const toolJsonSchema: v.GenericSchema<ToolJson> = v.lazy(() =>
  v.union([
    v.string(),
    v.number(),
    v.boolean(),
    v.null(),
    v.array(toolJsonSchema),
    v.record(v.string(), toolJsonSchema),
  ]),
);

export function createSurfaceRequestTools(
  agentId: string,
  target: ScopedTarget,
  profile: TargetProfile,
  ledger: CampaignLedger,
  coordinator: AdaptiveCoordinator,
  artifacts: ProofArtifactStore,
  adapters: BoundedToolAdapters,
  verification: VerificationEngine,
  dispatch: (action: CampaignAction) => void,
) {
  const mapAttackSurface = defineTool({
    name: NON_REST_AGENT_TOOLS.mapAttackSurface,
    description:
      "Map browser-observed requests and supplied OpenAPI operations into a REST attack surface. Use this first.",
    async run() {
      const map = await adapters.discovery.map();
      const operations = map.routeDetails
        .filter(({ scope }) => scope === undefined || scope === "attackable")
        .flatMap(({ path, methods }) => methods.map((method) => ({ method, path })));
      coordinator.discoverOperations(operations);
      dispatch({
        type: "operations-discovered",
        operations,
      });
      return {
        output: v.parse(toolJsonSchema, JSON.parse(JSON.stringify(map))),
      };
    },
  });
  const request = defineTool({
    name: "http_request",
    description:
      "Issue one scope-enforced REST request to a discovered path or configured attackable URL. Responses are capped.",
    input: v.object({
      path: v.string(),
      method: methodSchema,
      headers: v.optional(v.record(v.string(), v.string())),
      body: v.optional(v.string()),
      actorId: v.picklist([actorIds.anonymous, ...(profile.actorIds ?? [])]),
      sampleId: v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(80))),
    }),
    async run({ data }) {
      const requestedImpact =
        verification.impactLevelFor(data) ??
        (artifacts.hasIssuedChallenge(JSON.stringify(data))
          ? "bounded"
          : ["GET", "HEAD", "OPTIONS"].includes(data.method)
            ? "observation"
            : "state-change");
      target.assertImpactLevel(requestedImpact);
      const { observation: result, reused } = await ledger.request(
        {
          agentId,
          path: data.path,
          method: data.method,
          headers: data.headers,
          body: data.body,
          actorId: data.actorId,
          sampleId: data.sampleId,
        },
        () => {
          if (!coordinator.canRequest(agentId)) {
            throw new Error(`Coordinator request allocation exhausted for ${agentId}`);
          }
          return target.request(data);
        },
      );
      const output: HttpRequestToolOutput = {
        method: result.method ?? data.method,
        status: result.status,
        path: result.path,
        body: JSON.stringify(result.body),
        truncated: result.truncated ?? false,
        reused,
      };
      if (result.contentType !== undefined) output.contentType = result.contentType;
      if (result.redirectLocation !== undefined) output.redirectLocation = result.redirectLocation;
      if (result.redirected !== undefined) output.redirected = result.redirected;
      if (result.durationMs !== undefined) output.durationMs = result.durationMs;
      return { output };
    },
  });
  return { mapAttackSurface, request };
}

type HttpRequestToolOutput = {
  method: string;
  status: number;
  path: string;
  body: string;
  truncated: boolean;
  reused: boolean;
  contentType?: string;
  redirectLocation?: string;
  redirected?: boolean;
  durationMs?: number;
};
