import { describe, expect, it } from "vitest";
import { InMemoryCampaignStore } from "./campaign-store.ts";
import {
  createCampaignBudget,
  createCampaignState,
  validationJobId,
  type FindingInput,
} from "./state.ts";

describe("campaign store runtime", () => {
  it("makes validation completion idempotent", () => {
    const store = campaignWithFinding(readOnlyFinding());
    const validation = {
      fingerprint: "other:GET:/health",
      status: "rejected" as const,
      evidence: "not reproduced",
      proof: {
        predicate: "internal-field-exposure" as const,
        passed: false,
        summary: "no",
        checks: [],
      },
      observations: [],
      reviewer: { assessment: "unsupported" as const, evidence: "no" },
    };
    store.apply({ type: "job-started", id: validationJobId(validation.fingerprint) });
    store.apply({ type: "validation", validation });
    store.apply({ type: "validation", validation });
    expect(store.checkpoint().runtime.jobs).toContainEqual(
      expect.objectContaining({ status: "completed", attempts: 1 }),
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
    const store = campaignWithFinding(stateChangingFinding());
    const id = validationJobId("business-logic:POST:/orders/{id}");
    store.apply({ type: "job-started", id });
    store.apply({ type: "job-mutation-started", id });
    store.apply({ type: "recover" });
    expect(store.checkpoint().runtime).toMatchObject({
      control: "halted",
      jobs: [expect.objectContaining({ status: "interrupted", attempts: 1 })],
    });
  });
  it("requeues retryable read-only stops but finalizes terminal job failures", () => {
    const store = campaignWithFinding(readOnlyFinding());
    const id = validationJobId("other:GET:/health");
    store.apply({ type: "job-started", id });
    store.apply({ type: "job-failed", id, error: "paused", retryable: true });
    store.apply({ type: "job-started", id });
    store.apply({ type: "job-failed", id, error: "exhausted", retryable: false });
    expect(store.checkpoint().runtime.jobs[0]).toMatchObject({ status: "failed", attempts: 2 });
  });
  it("does not quarantine a state-changing job that failed before target mutation began", () => {
    const store = campaignWithFinding(stateChangingFinding());
    const id = validationJobId("business-logic:POST:/orders/{id}");
    store.apply({ type: "job-started", id });
    store.apply({ type: "job-failed", id, error: "unavailable", retryable: false });
    expect(store.checkpoint().runtime).toMatchObject({
      control: "running",
      jobs: [expect.objectContaining({ status: "failed" })],
    });
  });
  it("persists pause, resume, and cancellation as idempotent control actions", () => {
    const store = new InMemoryCampaignStore([
      ["controlled", createCampaignState("http://127.0.0.1:8888", createCampaignBudget(6), 1)],
    ]);
    store.load("controlled");
    store.apply({ type: "pause", reason: "outside approved hours" });
    store.apply({ type: "pause", reason: "ignored" });
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
  const store = new InMemoryCampaignStore([
    ["campaign", createCampaignState("http://127.0.0.1:8888", createCampaignBudget(6), 1)],
  ]);
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
