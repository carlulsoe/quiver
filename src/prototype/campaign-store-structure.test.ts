import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CampaignSession } from "./campaign-session.ts";
import {
  serializeJsonlRecords,
  type DurableAppend,
  type JsonlRecord,
} from "./campaign-store-log.ts";
import { JsonlCampaignStore } from "./campaign-store.ts";
import { createCampaignBudget, createCampaignState } from "./state.ts";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("durable campaign store structure", () => {
  it("bounds writes, checkpoints, and log growth for repeated session transitions", () => {
    const directory = mkdtempSync(join(tmpdir(), "quiver-store-structure-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "campaigns.jsonl");
    const writes: Buffer[] = [];
    const store = new JsonlCampaignStore(path, [], { durableAppend: capturingAppend(writes) });
    const session = new CampaignSession({
      target: new URL("http://127.0.0.1:8888/"),
      profile: {
        id: "structural-bounds",
        displayName: "Structural bounds",
        objective: "Measure deterministic persistence structure.",
      },
      requestBudget: 30,
      explorerCount: 1,
      campaignStore: store,
    });

    for (let index = 0; index < 20; index += 1) {
      session.dispatch({ type: "request", phase: "exploration" });
    }

    const beforeControlReads = store.statistics();
    expect(Array.from({ length: 100 }, () => store.controlStatus())).toEqual(
      Array.from({ length: 100 }, () => "running"),
    );
    expect(store.statistics()).toEqual(beforeControlReads);
    store.close();

    const serialized = Buffer.concat(writes);
    const records = parseRecords(serialized);
    const statistics = store.statistics();

    // Before batching, this sequence produced 81 records, 40 checkpoints, 81 durable writes,
    // and 141,908 bytes because every action and derived event forced a full-state snapshot.
    expect(statistics).toEqual({
      durableWrites: 22,
      records: 43,
      actionRecords: 40,
      checkpointRecords: 2,
      fullStateRecords: 3,
      bytes: serialized.length,
    });
    expect(records).toHaveLength(43);
    expect(records.filter(({ kind }) => kind === "checkpoint")).toHaveLength(2);
    expect(statistics.bytes).toBeLessThan(30_000);
  });

  it("keeps the checkpoint cadence bounded inside one large durable batch", () => {
    const directory = mkdtempSync(join(tmpdir(), "quiver-store-batch-bound-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "campaigns.jsonl");
    const writes: Buffer[] = [];
    const store = new JsonlCampaignStore(
      path,
      [["durable", createCampaignState("http://127.0.0.1:8888/", createCampaignBudget(90), 1)]],
      { durableAppend: capturingAppend(writes) },
    );
    store.applyBatch(
      Array.from({ length: 70 }, () => ({ type: "request", phase: "exploration" }) as const),
    );
    store.close();

    const kinds = parseRecords(Buffer.concat(writes)).map(({ kind }) => kind);
    let consecutiveActions = 0;
    let maximumConsecutiveActions = 0;
    for (const kind of kinds) {
      consecutiveActions = kind === "action" ? consecutiveActions + 1 : 0;
      maximumConsecutiveActions = Math.max(maximumConsecutiveActions, consecutiveActions);
    }

    expect(maximumConsecutiveActions).toBe(32);
    expect(store.statistics()).toMatchObject({
      durableWrites: 3,
      records: 74,
      actionRecords: 70,
      checkpointRecords: 3,
      fullStateRecords: 4,
    });
  });
});

function capturingAppend(writes: Buffer[]): DurableAppend {
  return (_descriptor, records) => {
    const bytes = serializeJsonlRecords(records);
    writes.push(bytes);
    return bytes.length;
  };
}

function parseRecords(bytes: Buffer): JsonlRecord[] {
  return bytes
    .toString("utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as JsonlRecord);
}
