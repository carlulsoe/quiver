import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { InMemoryCampaignStore, JsonlCampaignStore, type CampaignStore } from "./campaign-store.ts";
import { createCampaignBudget, createCampaignState } from "./state.ts";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

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

  it("replays durable actions and checksum-verified checkpoints from JSONL", () => {
    const directory = mkdtempSync(join(tmpdir(), "quiver-campaign-store-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "campaigns.jsonl");
    const initial = createCampaignState("http://127.0.0.1:8888", createCampaignBudget(6), 1);
    const store = new JsonlCampaignStore(path, [["durable", initial]]);

    store.load("durable");
    store.apply({ type: "phase", phase: "exploring" });
    store.apply({ type: "request", phase: "exploration" });
    expect(store.checkpoint().requests.total).toBe(1);
    store.close();

    const reopened = new JsonlCampaignStore(path);
    expect(reopened.load("durable")).toMatchObject({
      phase: "exploring",
      requests: { total: 1, exploration: 1, validation: 0 },
    });
    reopened.close();
  });

  it("does not persist an action rejected by the reducer", () => {
    const directory = mkdtempSync(join(tmpdir(), "quiver-campaign-store-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "campaigns.jsonl");
    const initial = createCampaignState("http://127.0.0.1:8888", createCampaignBudget(6), 1);
    const store = new JsonlCampaignStore(path, [["durable", initial]]);

    store.load("durable");
    expect(() =>
      store.apply({
        type: "operations-discovered",
        operations: [{ method: "GET", path: "/%E0%A4%A" }],
      }),
    ).toThrow();
    store.close();

    expect(readFileSync(path, "utf8").trim().split("\n")).toHaveLength(1);
    const reopened = new JsonlCampaignStore(path);
    expect(reopened.load("durable").discoveredOperations).toEqual([]);
    reopened.close();
  });

  it("ignores a torn final JSONL write during crash recovery", () => {
    const directory = mkdtempSync(join(tmpdir(), "quiver-campaign-store-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "campaigns.jsonl");
    const initial = createCampaignState("http://127.0.0.1:8888", createCampaignBudget(6), 1);
    const store = new JsonlCampaignStore(path, [["durable", initial]]);
    store.load("durable");
    store.apply({ type: "phase", phase: "exploring" });
    store.apply({ type: "pause", reason: "Vindue lukket — sikkerhed først 🛡️" });
    store.checkpoint();
    store.close();
    appendFileSync(path, '{"version":1,"campaignId":"durable"');

    const reopened = new JsonlCampaignStore(path);
    expect(reopened.load("durable")).toMatchObject({
      phase: "exploring",
      runtime: { control: "paused", controlReason: "Vindue lukket — sikkerhed først 🛡️" },
    });
    reopened.close();
  });

  it("holds an exclusive process lock for the durable log lifetime", () => {
    const directory = mkdtempSync(join(tmpdir(), "quiver-campaign-store-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "campaigns.jsonl");
    const first = new JsonlCampaignStore(path);

    expect(() => new JsonlCampaignStore(path)).toThrow("already owned by another process");
    first.close();
    const second = new JsonlCampaignStore(path);
    second.close();
  });

  it("reopens a lock file after the owning process lock is released", () => {
    const directory = mkdtempSync(join(tmpdir(), "quiver-campaign-store-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "campaigns.jsonl");
    writeFileSync(`${path}.lock`, JSON.stringify({ pid: 2_147_483_647, nonce: "stale" }));

    const store = new JsonlCampaignStore(path);

    store.close();
  });
});
