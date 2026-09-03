import { describe, expect, it } from "vitest";
import {
  campaignActionOwners,
  createCampaignBudget,
  createCampaignState,
  reduceCampaign,
} from "./state.ts";
import type { FindingInput } from "./state.ts";

describe("campaign action ownership", () => {
  it("assigns every persisted discriminant to exactly one reducer", () => {
    expect(campaignActionOwners).toEqual({
      phase: "campaign",
      agent: "campaign",
      "agent-spawned": "campaign",
      "coordinator-snapshot": "campaign",
      request: "campaign",
      "reclaim-exploration-budget": "campaign",
      "request-tested": "campaign",
      "routes-discovered": "campaign",
      "operations-discovered": "campaign",
      finding: "campaign",
      validation: "campaign",
      "exploit-chain": "campaign",
      "exploit-chain-validation": "campaign",
      failed: "campaign",
      pause: "runtime",
      resume: "runtime",
      cancel: "runtime",
      halt: "runtime",
      recover: "runtime",
      "job-started": "runtime",
      "job-mutation-started": "runtime",
      "job-failed": "runtime",
      "runtime-success": "runtime",
      "runtime-failure": "runtime",
      "run-event": "runtime",
      "mission-started": "runtime",
      "mission-updated": "runtime",
      "history-elapsed": "runtime",
    });
  });

  it("routes representative safety, budget, finding, and history actions", () => {
    let state = createCampaignState("http://127.0.0.1:8888/", createCampaignBudget(6), 1);
    state = reduceCampaign(state, { type: "request", phase: "exploration" });
    state = reduceCampaign(state, { type: "reclaim-exploration-budget" });
    state = reduceCampaign(state, { type: "finding", finding });
    state = reduceCampaign(state, { type: "pause", reason: "testing window ended" });
    state = reduceCampaign(state, {
      type: "run-event",
      event: {
        sequence: 1,
        elapsedMs: 25,
        type: "request",
        data: { phase: "exploration", method: "GET", path: "/health" },
      },
    });

    expect(state).toMatchObject({
      budget: { total: 6, exploration: 1, validation: 5 },
      requests: { total: 1, exploration: 1, validation: 0 },
      runtime: { control: "paused", controlReason: "testing window ended" },
      history: { durationMs: 25 },
    });
    expect(state.findings).toHaveLength(1);
    expect(state.runtime.jobs).toEqual([
      expect.objectContaining({ kind: "validation", status: "queued" }),
    ]);
    expect(state.history.events).toEqual([expect.objectContaining({ sequence: 1 })]);
  });
});

const finding: FindingInput = {
  agentId: "explorer-1",
  title: "Health details",
  category: "other",
  severity: "low",
  cwe: "CWE-200",
  endpoint: "/health",
  method: "GET",
  resource: "health",
  rationale: "The response exposes a build identifier.",
  impact: "A caller can fingerprint the service.",
  mitigation: "Remove internal build metadata.",
  reproduction: [{ path: "/health", actorId: "anonymous" }],
  proof: { type: "internal-field-exposure", requestIndex: 0, evidencePointers: ["/build"] },
};
