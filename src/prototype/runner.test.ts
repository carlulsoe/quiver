import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createCampaignIdentity } from "./campaign-identity.ts";
import { InMemoryCampaignStore, JsonlCampaignStore } from "./campaign-store.ts";
import { runCampaign } from "./runner.ts";
import { createCampaignBudget, createCampaignState, reduceCampaign } from "./state.ts";

describe("campaign runner", () => {
  it("records executor construction failures in campaign state", async () => {
    const run = await runCampaign({
      target: new URL("http://127.0.0.1:8888/"),
      profile: {
        id: "construction-failure",
        displayName: "Construction failure",
        objective: "Persist setup failures instead of losing the campaign outcome.",
      },
      modelRouter: {
        route() {
          throw new Error("route construction failed");
        },
      },
    });

    expect(run.state).toMatchObject({
      phase: "failed",
      error: "route construction failed",
    });
  });

  it("rejects a checkpoint created for another target profile", async () => {
    const state = {
      ...createCampaignState("http://127.0.0.1:8888/", createCampaignBudget(6), 1),
      identity: {
        schemaVersion: 2 as const,
        profileId: "original-profile",
        configurationFingerprint: "original-configuration",
        resumable: true,
      },
    };
    const campaignStore = new InMemoryCampaignStore([["resumed", state]]);

    await expect(
      runCampaign({
        campaignId: "resumed",
        campaignStore,
        target: new URL("http://127.0.0.1:8888/"),
        profile: {
          id: "different-profile",
          displayName: "Different profile",
          objective: "Do not inherit another profile's campaign state.",
        },
      }),
    ).rejects.toThrow("belongs to profile original-profile, not different-profile");
  });

  it("rejects a checkpoint when its safety-relevant configuration changed", async () => {
    const state = {
      ...createCampaignState("http://127.0.0.1:8888/", createCampaignBudget(6), 1),
      identity: {
        schemaVersion: 2 as const,
        profileId: "same-profile",
        configurationFingerprint: "an-obsolete-configuration",
        resumable: true,
      },
    };
    const campaignStore = new InMemoryCampaignStore([["resumed", state]]);

    await expect(
      runCampaign({
        campaignId: "resumed",
        campaignStore,
        target: new URL("http://127.0.0.1:8888/"),
        profile: {
          id: "same-profile",
          displayName: "Same profile",
          objective: "Do not resume under changed safety settings.",
          runtimeSafety: { requestsPerSecond: 1 },
        },
      }),
    ).rejects.toThrow("configuration does not match");
  });

  it("loads a paused checkpoint without resetting its spent budget", async () => {
    const target = new URL("http://127.0.0.1:8888/");
    const profile = {
      id: "resume-test",
      displayName: "Resume test",
      objective: "Do not reset stored budgets.",
    };
    let state = createCampaignState(
      target.href,
      createCampaignBudget(6),
      1,
      createCampaignIdentity({ target, profile, requestBudget: 6, explorerCount: 1 }),
    );
    state = reduceCampaign(state, { type: "phase", phase: "exploring" });
    state = reduceCampaign(state, { type: "request", phase: "exploration" });
    state = reduceCampaign(state, { type: "pause", reason: "operator window ended" });
    const campaignStore = new InMemoryCampaignStore([["resumed", state]]);

    const run = await runCampaign({
      campaignId: "resumed",
      campaignStore,
      target,
      profile,
      requestBudget: 6,
      explorerCount: 1,
    });

    expect(run.state).toMatchObject({
      phase: "exploring",
      requests: { total: 1, exploration: 1 },
      runtime: { control: "paused", controlReason: "operator window ended" },
    });
  });

  it("rejects durable resume when callback-owned configuration is not bound", async () => {
    const target = new URL("http://127.0.0.1:8888/");
    const profile = {
      id: "unbound-callback",
      displayName: "Unbound callback",
      objective: "Fail closed when callback configuration cannot be identified.",
      authenticate: async () => ({ authContext: "closed-over-value" }),
    };
    const state = createCampaignState(
      target.href,
      createCampaignBudget(6),
      1,
      createCampaignIdentity({ target, profile, requestBudget: 6, explorerCount: 1 }),
    );
    const campaignStore = new InMemoryCampaignStore([["unbound", state]]);

    await expect(
      runCampaign({
        campaignId: "unbound",
        campaignStore,
        target,
        profile,
        requestBudget: 6,
        explorerCount: 1,
      }),
    ).rejects.toThrow("must declare callbackConfigurationFingerprint");
  });

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
    const writer = new JsonlCampaignStore(path, [["resumed-history", state]]);
    writer.close();
    const campaignStore = new JsonlCampaignStore(path);
    try {
      const run = await runCampaign({
        campaignId: "resumed-history",
        campaignStore,
        target,
        profile,
        requestBudget: 6,
        explorerCount: 1,
      });

      expect(run.events).toContainEqual(
        expect.objectContaining({
          sequence: 1,
          data: expect.objectContaining({ path: "/before-crash" }),
        }),
      );
      expect(run.usage.totalTokens).toBe(7);
      expect(run.durationMs).toBe(250);

      const repeated = await runCampaign({
        campaignId: "resumed-history",
        campaignStore,
        target,
        profile,
        requestBudget: 6,
        explorerCount: 1,
      });
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
