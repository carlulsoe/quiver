import { describe, expect, it } from "vitest";
import { InMemoryCampaignStore, type CampaignStore } from "./campaign-store.ts";
import { createCampaignBudget, createCampaignState } from "./state.ts";

describe("campaign store", () => {
  it("loads, applies, and checkpoints a campaign through the store interface", () => {
    const initial = createCampaignState("http://127.0.0.1:8888", createCampaignBudget(6), 1);
    const campaignStore: CampaignStore = new InMemoryCampaignStore([["campaign-1", initial]]);

    expect(campaignStore.load("campaign-1").phase).toBe("starting");
    campaignStore.apply({ type: "phase", phase: "exploring" });
    const checkpoint = campaignStore.checkpoint();

    expect(checkpoint.phase).toBe("exploring");
    checkpoint.phase = "failed";
    expect(campaignStore.checkpoint().phase).toBe("exploring");
  });

  it("keeps campaigns isolated when the active campaign changes", () => {
    const budget = createCampaignBudget(6);
    const campaignStore = new InMemoryCampaignStore([
      ["first", createCampaignState("http://127.0.0.1:8001", budget, 1)],
      ["second", createCampaignState("http://127.0.0.1:8002", budget, 1)],
    ]);

    campaignStore.load("first");
    campaignStore.apply({ type: "phase", phase: "exploring" });
    expect(campaignStore.load("second").phase).toBe("starting");
    expect(campaignStore.load("first").phase).toBe("exploring");
  });
});
