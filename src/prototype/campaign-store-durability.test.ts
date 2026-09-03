import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonlCampaignStore } from "./campaign-store.ts";
import {
  createCampaignBudget,
  createCampaignState,
  reduceCampaign,
  validationJobId,
  type CampaignAction,
  type CampaignControlStatus,
  type FindingInput,
} from "./state.ts";

const temporaryDirectories: string[] = [];

interface TestStorePath {
  directory: string;
  path: string;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("durable campaign crash boundaries", () => {
  it("replays actions written before the next periodic checkpoint", () => {
    const { directory, path } = storePath("pre-checkpoint");
    const crashPath = join(directory, "crashed.jsonl");
    const store = new JsonlCampaignStore(path, [["durable", initialState()]], {
      checkpointActionInterval: 100,
    });
    store.apply({ type: "request", phase: "exploration" });
    store.apply({ type: "request", phase: "exploration" });
    writeFileSync(crashPath, readFileSync(path));

    const recovered = new JsonlCampaignStore(crashPath);
    expect(recovered.load("durable").requests).toEqual({
      total: 2,
      exploration: 2,
      validation: 0,
    });
    recovered.close();
    store.close();
  });

  it("replays through a periodic checkpoint and later WAL actions", () => {
    const { directory, path } = storePath("periodic-checkpoint");
    const crashPath = join(directory, "crashed.jsonl");
    const store = new JsonlCampaignStore(path, [["durable", initialState()]], {
      checkpointActionInterval: 4,
    });
    for (let index = 0; index < 5; index += 1) {
      store.apply({ type: "request", phase: "exploration" });
    }
    writeFileSync(crashPath, readFileSync(path));

    expect(store.statistics()).toMatchObject({ actionRecords: 5, checkpointRecords: 1 });
    const recovered = new JsonlCampaignStore(crashPath);
    expect(recovered.load("durable").requests.total).toBe(5);
    recovered.close();
    store.close();
  });

  it("quarantines every crash boundary after a flushed mutation marker", () => {
    const { directory, path } = storePath("mutation-boundaries");
    const state = runningStateChangingJob();
    const store = new JsonlCampaignStore(path, [["durable", state]], {
      checkpointActionInterval: 100,
    });
    const id = validationJobId("business-logic:POST:/orders/{id}");
    store.applyBatch([
      { type: "job-mutation-started", id },
      {
        type: "run-event",
        event: {
          sequence: 1,
          elapsedMs: 1,
          type: "state",
          data: { action: "job-mutation-started", phase: "starting" },
        },
      },
    ]);
    const lines = readFileSync(path, "utf8").trim().split("\n");

    const beforeMarkerPath = join(directory, "crashed-1.jsonl");
    writeFileSync(beforeMarkerPath, `${lines[0]}\n`);
    const beforeMarker = new JsonlCampaignStore(beforeMarkerPath);
    beforeMarker.load("durable");
    beforeMarker.apply({ type: "recover" });
    expect(beforeMarker.checkpoint().runtime).toMatchObject({
      control: "running",
      jobs: [expect.objectContaining({ status: "queued", mutationStarted: false })],
    });
    beforeMarker.close();

    for (const boundary of [2, 3]) {
      const crashPath = join(directory, `crashed-${boundary}.jsonl`);
      const tornTail = boundary === 2 ? '{"version":1' : "";
      writeFileSync(crashPath, `${lines.slice(0, boundary).join("\n")}\n${tornTail}`);
      const recovered = new JsonlCampaignStore(crashPath);
      recovered.load("durable");
      recovered.apply({ type: "recover" });
      expect(recovered.checkpoint().runtime).toMatchObject({
        control: "halted",
        jobs: [expect.objectContaining({ status: "interrupted", mutationStarted: true })],
      });
      recovered.close();
    }
    store.close();
  });

  it.each([
    [{ type: "pause", reason: "window ended" }, "paused"],
    [{ type: "cancel", reason: "operator stopped" }, "cancelled"],
    [{ type: "halt", reason: "safety threshold" }, "halted"],
  ] satisfies readonly (readonly [CampaignAction, CampaignControlStatus])[])(
    "recovers the %s lifecycle boundary",
    (action, expected) => {
      const { path } = storePath(`control-${action.type}`);
      const store = new JsonlCampaignStore(path, [["durable", initialState()]]);
      store.apply(action);
      store.close();

      const recovered = new JsonlCampaignStore(path);
      expect(recovered.load("durable").runtime.control).toBe(expected);
      recovered.close();
    },
  );
});

function storePath(name: string): TestStorePath {
  const directory = mkdtempSync(join(tmpdir(), `quiver-${name}-`));
  temporaryDirectories.push(directory);
  return { directory, path: join(directory, "campaigns.jsonl") };
}

function initialState() {
  return createCampaignState("http://127.0.0.1:8888/", createCampaignBudget(6), 1);
}

function runningStateChangingJob() {
  let state = reduceCampaign(initialState(), { type: "finding", finding: stateChangingFinding });
  state = reduceCampaign(state, {
    type: "job-started",
    id: validationJobId("business-logic:POST:/orders/{id}"),
  });
  return state;
}

const stateChangingFinding: FindingInput = {
  agentId: "explorer-1",
  title: "Order transition",
  category: "business-logic",
  severity: "high",
  cwe: "CWE-841",
  endpoint: "/orders/{id}",
  method: "POST",
  resource: "order-1",
  rationale: "The transition bypasses workflow checks.",
  impact: "An order can enter an invalid state.",
  mitigation: "Enforce allowed workflow transitions.",
  impactLevel: "state-change",
  reproduction: [{ path: "/orders/1", method: "POST", actorId: "anonymous" }],
  proof: {
    type: "state-transition",
    policyId: "order-transition",
    transitionRequestIndex: 0,
    beforeRequestIndex: 0,
    afterRequestIndex: 0,
  },
};
