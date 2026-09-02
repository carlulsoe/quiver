import { describe, expect, it } from "vitest";
import { createCampaignState, reduceCampaign } from "./state.ts";

describe("campaign state coordination", () => {
  it("exposes completed exploration tests to campaign observers", () => {
    const initial = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    const tested = reduceCampaign(initial, {
      type: "request-tested",
      request: {
        agentId: "explorer-1",
        path: "/api/items/42",
        actorId: "ordinary-user",
        status: 200,
      },
    });
    expect(tested.testedRequests).toEqual([
      { agentId: "explorer-1", path: "/api/items/42", actorId: "ordinary-user", status: 200 },
    ]);
  });
  it("persists coordinator decisions and dynamically spawned specialists", () => {
    let state = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    state = reduceCampaign(state, {
      type: "agent-spawned",
      id: "specialist-1",
      role: "specialist",
    });
    state = reduceCampaign(state, {
      type: "coordinator-snapshot",
      snapshot: {
        ...state.coordination,
        revision: 1,
        coverage: {
          discoveredOperations: 4,
          testedOperations: 2,
          operationCoverage: 0.5,
          testedAccessModes: 3,
          totalAccessModes: 8,
          accessModeCoverage: 0.375,
        },
      },
    });
    expect(state.agents).toContainEqual({
      id: "specialist-1",
      role: "specialist",
      status: "queued",
    });
    expect(state.coordination).toMatchObject({
      revision: 1,
      coverage: { operationCoverage: 0.5, accessModeCoverage: 0.375 },
    });
  });
});
