import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { InMemoryCampaignStore, JsonlCampaignStore, type CampaignStore } from "./campaign-store.ts";
import {
  createCampaignBudget,
  createCampaignState,
  validationJobId,
  type FindingInput,
  type FindingValidation,
} from "./state.ts";

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

  it("makes validation completion idempotent", () => {
    const store = campaignWithFinding(readOnlyFinding());
    const validation = rejectedValidation("other:GET:/health");

    store.apply({ type: "job-started", id: validationJobId(validation.fingerprint) });
    store.apply({ type: "validation", validation });
    store.apply({ type: "validation", validation });

    const checkpoint = store.checkpoint();
    expect(checkpoint.validations).toHaveLength(1);
    expect(checkpoint.runtime.jobs).toContainEqual(
      expect.objectContaining({
        id: validationJobId(validation.fingerprint),
        status: "completed",
        attempts: 1,
      }),
    );
  });

  it("recovers read-only jobs but halts instead of repeating state-changing attempts", () => {
    const readOnlyStore = campaignWithFinding(readOnlyFinding());
    const readOnlyId = validationJobId("other:GET:/health");
    readOnlyStore.apply({ type: "job-started", id: readOnlyId });
    readOnlyStore.apply({ type: "recover" });
    expect(readOnlyStore.checkpoint().runtime.jobs[0]).toMatchObject({
      status: "queued",
      attempts: 1,
    });

    const stateChangingStore = campaignWithFinding(stateChangingFinding());
    const stateChangingId = validationJobId("business-logic:POST:/orders/{id}");
    stateChangingStore.apply({ type: "job-started", id: stateChangingId });
    stateChangingStore.apply({ type: "recover" });
    expect(stateChangingStore.checkpoint().runtime).toMatchObject({
      control: "halted",
      jobs: [
        expect.objectContaining({
          id: stateChangingId,
          status: "interrupted",
          attempts: 1,
        }),
      ],
    });
  });

  it("requeues retryable read-only stops but finalizes terminal job failures", () => {
    const store = campaignWithFinding(readOnlyFinding());
    const id = validationJobId("other:GET:/health");

    store.apply({ type: "job-started", id });
    store.apply({ type: "job-failed", id, error: "Campaign is paused", retryable: true });
    expect(store.checkpoint().runtime.jobs[0]).toMatchObject({ status: "queued", attempts: 1 });

    store.apply({ type: "job-started", id });
    store.apply({ type: "job-failed", id, error: "Final budget exhausted", retryable: false });
    expect(store.checkpoint().runtime.jobs[0]).toMatchObject({ status: "failed", attempts: 2 });

    const stateChangingStore = campaignWithFinding(stateChangingFinding());
    const stateChangingId = validationJobId("business-logic:POST:/orders/{id}");
    stateChangingStore.apply({ type: "job-started", id: stateChangingId });
    stateChangingStore.apply({
      type: "job-failed",
      id: stateChangingId,
      error: "Testing window closed during replay",
      retryable: true,
    });
    expect(stateChangingStore.checkpoint().runtime).toMatchObject({
      control: "halted",
      jobs: [expect.objectContaining({ status: "interrupted", attempts: 1 })],
    });
  });

  it("persists pause, resume, and cancellation as idempotent control actions", () => {
    const state = createCampaignState("http://127.0.0.1:8888", createCampaignBudget(6), 1);
    const store = new InMemoryCampaignStore([["controlled", state]]);
    store.load("controlled");

    store.apply({ type: "pause", reason: "outside approved hours" });
    store.apply({ type: "pause", reason: "ignored duplicate" });
    expect(store.checkpoint().runtime.controlReason).toBe("outside approved hours");
    store.apply({ type: "resume" });
    store.apply({ type: "cancel", reason: "operator cancelled" });
    store.apply({ type: "resume" });

    expect(store.checkpoint().runtime).toMatchObject({
      control: "cancelled",
      controlReason: "operator cancelled",
    });
  });
});

function campaignWithFinding(finding: FindingInput): InMemoryCampaignStore {
  const state = createCampaignState("http://127.0.0.1:8888", createCampaignBudget(6), 1);
  const store = new InMemoryCampaignStore([["campaign", state]]);
  store.load("campaign");
  store.apply({ type: "finding", finding });
  return store;
}

function readOnlyFinding(): FindingInput {
  return {
    agentId: "explorer-1",
    title: "Health details",
    category: "other",
    severity: "low",
    cwe: "CWE-200",
    endpoint: "/health",
    method: "GET",
    resource: "health",
    rationale: "test",
    impact: "test",
    mitigation: "test",
    impactLevel: "observation",
    reproduction: [{ path: "/health", actorId: "anonymous" }],
    proof: { type: "internal-field-exposure", requestIndex: 0, evidencePointers: ["/build"] },
  };
}

function stateChangingFinding(): FindingInput {
  return {
    ...readOnlyFinding(),
    title: "Order transition",
    category: "business-logic",
    endpoint: "/orders/{id}",
    method: "POST",
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
}

function rejectedValidation(fingerprint: string): FindingValidation {
  return {
    fingerprint,
    status: "rejected",
    evidence: "not reproduced",
    proof: { predicate: "internal-field-exposure", passed: false, summary: "no", checks: [] },
    observations: [],
    reviewer: { assessment: "unsupported", evidence: "no" },
  };
}
