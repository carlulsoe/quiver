import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createCampaignIdentity } from "./campaign-identity.ts";
import { JsonlCampaignStore } from "./campaign-store.ts";
import { runCampaign } from "./runner.ts";
import { createCampaignBudget, createCampaignState, reduceCampaign } from "./state.ts";

describe("campaign runner history", () => {
  it("retains pre-crash activity and usage after reopening a durable campaign", async () => {
    const target = new URL("http://127.0.0.1:8888/");
    const profile = {
      id: "history-test",
      displayName: "History test",
      objective: "Retain the complete durable trace.",
    };
    let state = createCampaignState(
      target.href,
      createCampaignBudget(6),
      1,
      createCampaignIdentity({ target, profile, requestBudget: 6, explorerCount: 1 }),
    );
    state = reduceCampaign(state, { type: "phase", phase: "exploring" });
    state = reduceCampaign(state, { type: "phase", phase: "validating" });
    state = reduceCampaign(state, { type: "phase", phase: "complete" });
    state = {
      ...state,
      history: {
        durationMs: 250,
        usage: usage(7),
        missionUsage: [],
        events: [
          {
            sequence: 1,
            elapsedMs: 200,
            type: "request",
            data: { phase: "exploration", method: "GET", path: "/before-crash" },
          },
        ],
      },
    };
    const directory = mkdtempSync(join(tmpdir(), "quiver-runner-resume-"));
    const path = join(directory, "campaigns.jsonl");
    new JsonlCampaignStore(path, [["resumed-history", state]]).close();
    const campaignStore = new JsonlCampaignStore(path);
    try {
      const options = {
        campaignId: "resumed-history",
        campaignStore,
        target,
        profile,
        requestBudget: 6,
        explorerCount: 1,
      };
      const run = await runCampaign(options);
      expect(run.events).toContainEqual(
        expect.objectContaining({
          sequence: 1,
          data: expect.objectContaining({ path: "/before-crash" }),
        }),
      );
      expect(run.usage.totalTokens).toBe(7);
      expect(run.durationMs).toBe(250);
      const repeated = await runCampaign(options);
      expect(repeated.durationMs).toBe(250);
      expect(repeated.events).toHaveLength(1);
    } finally {
      campaignStore.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
function usage(totalTokens: number) {
  return {
    input: totalTokens,
    output: 0,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
}
