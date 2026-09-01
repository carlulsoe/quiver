import { describe, expect, it } from "vitest";
import { InMemoryCampaignStore } from "./campaign-store.ts";
import { runCampaign } from "./runner.ts";
import { createCampaignBudget, createCampaignState, reduceCampaign } from "./state.ts";

describe("campaign runner", () => {
  it("refuses to restart a stored campaign with spent budget", async () => {
    let state = createCampaignState("http://127.0.0.1:8888/", createCampaignBudget(6), 1);
    state = reduceCampaign(state, { type: "phase", phase: "exploring" });
    state = reduceCampaign(state, { type: "request", phase: "exploration" });
    const campaignStore = new InMemoryCampaignStore([["resumed", state]]);

    await expect(
      runCampaign({
        campaignId: "resumed",
        campaignStore,
        target: new URL("http://127.0.0.1:8888/"),
        profile: {
          id: "resume-test",
          displayName: "Resume test",
          objective: "Do not reset stored budgets.",
        },
      }),
    ).rejects.toThrow("campaign resume is not supported");
  });
});
