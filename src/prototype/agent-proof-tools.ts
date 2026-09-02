import { defineTool } from "@flue/runtime";
import type { AdaptiveCoordinator } from "./adaptive-coordinator.ts";
import type { CampaignLedger } from "./campaign-ledger.ts";
import type { BoundedToolAdapters } from "./tool-adapters.ts";
import { NON_REST_AGENT_TOOLS } from "./tool-adapters.ts";
import * as v from "valibot";

export function createProofObservationTools(
  agentId: string,
  ledger: CampaignLedger,
  coordinator: AdaptiveCoordinator,
  adapters: BoundedToolAdapters,
) {
  const review = defineTool({
    name: "review_campaign",
    description:
      "Read the shared ledger and receive a fresh, non-overlapping assignment based on uncovered routes and incoming request evidence.",
    run() {
      const snapshot = ledger.snapshot();
      const assignment = coordinator.assign(agentId);
      return {
        output: {
          testedRequests: snapshot.testedRequests.map((request) => ({ ...request })),
          findings: snapshot.findings.map((finding) => ({ ...finding })),
          assignment: {
            ...assignment,
            tasks: assignment.tasks.map((task) => ({ ...task })),
            evidenceSignals: [...assignment.evidenceSignals],
            hypotheses: assignment.hypotheses.map((hypothesis) => ({
              ...hypothesis,
              evidenceSignals: [...hypothesis.evidenceSignals],
            })),
            budget: { ...assignment.budget },
          },
        },
      };
    },
  });
  const createOastProbe = defineTool({
    name: NON_REST_AGENT_TOOLS.createOastProbe,
    description: "Issue a campaign-local loopback HTTP callback URL with an unguessable token.",
    run() {
      const { probeId, token, url } = adapters.oast.issue();
      return { output: { probeId, token, url } };
    },
  });
  const createBrowserProbe = defineTool({
    name: NON_REST_AGENT_TOOLS.createBrowserProbe,
    description: "Issue an unguessable marker for one browser-visible-effect proof attempt.",
    run() {
      const { probeId, marker } = adapters.browser.issue();
      return { output: { probeId, marker } };
    },
  });
  const pollOastProbe = defineTool({
    name: NON_REST_AGENT_TOOLS.pollOastProbe,
    description: "Wait briefly for a callback to one issued OAST probe.",
    input: v.object({ probeId: v.string(), token: v.string() }),
    async run({ data }) {
      const callback = await adapters.oast.poll(data);
      return {
        output: {
          observed: callback !== undefined,
          callback: callback
            ? {
                probeId: callback.probeId,
                token: callback.token,
                protocol: callback.protocol,
                method: callback.method,
                path: callback.path,
                observedAt: callback.observedAt,
              }
            : null,
        },
      };
    },
  });
  const observeBrowserEffect = defineTool({
    name: NON_REST_AGENT_TOOLS.observeBrowserEffect,
    description:
      "Open one same-origin page with a target-policy-owned request cap and record an issued marker only when it is visibly observed.",
    input: v.object({
      policyId: v.string(),
      probeId: v.string(),
    }),
    async run({ data }) {
      const evidence = await adapters.browser.observe(data);
      return {
        output: {
          observed: evidence !== undefined,
          evidence: evidence
            ? {
                probeId: evidence.probeId,
                path: evidence.path,
                kind: evidence.kind,
                value: evidence.value,
              }
            : null,
        },
      };
    },
  });
  const observeBrowserStateTransition = defineTool({
    name: NON_REST_AGENT_TOOLS.observeBrowserStateTransition,
    description:
      "Run one policy-owned cross-origin browser page with victim cookies and record only its exact state-changing request.",
    input: v.object({ policyId: v.string() }),
    async run({ data }) {
      const evidence = await adapters.browser.observeStateTransition(data);
      return {
        output: {
          observed: evidence !== undefined,
          evidence: evidence ? { ...evidence } : null,
        },
      };
    },
  });
  return {
    review,
    createOastProbe,
    createBrowserProbe,
    pollOastProbe,
    observeBrowserEffect,
    observeBrowserStateTransition,
  };
}
