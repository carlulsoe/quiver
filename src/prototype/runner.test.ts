import { describe, expect, it } from "vitest";
import { InMemoryCampaignStore } from "./campaign-store.ts";
import { runCampaign } from "./runner.ts";
import { createCampaignBudget, createCampaignState, reduceCampaign } from "./state.ts";

describe("campaign runner", () => {
  it("loads a paused checkpoint without resetting its spent budget", async () => {
    let state = createCampaignState("http://127.0.0.1:8888/", createCampaignBudget(6), 1);
    state = reduceCampaign(state, { type: "phase", phase: "exploring" });
    state = reduceCampaign(state, { type: "request", phase: "exploration" });
    state = reduceCampaign(state, { type: "pause", reason: "operator window ended" });
    const campaignStore = new InMemoryCampaignStore([["resumed", state]]);

    const run = await runCampaign({
      campaignId: "resumed",
      campaignStore,
      target: new URL("http://127.0.0.1:8888/"),
      profile: {
        id: "resume-test",
        displayName: "Resume test",
        objective: "Do not reset stored budgets.",
      },
    });

    expect(run.state).toMatchObject({
      phase: "exploring",
      requests: { total: 1, exploration: 1 },
      runtime: { control: "paused", controlReason: "operator window ended" },
    });
  });
});
