import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CampaignSession } from "./campaign-session.ts";
import { JsonlCampaignStore } from "./campaign-store.ts";
import { CampaignPausedError, RuntimeSafetyController } from "./runtime-safety.ts";
import type { CampaignAction, CampaignState } from "./state.ts";

describe("campaign session control synchronization", () => {
  it("reads externally persisted control state without writing or checkpointing", () => {
    withDurableSession("external-control", ({ session, store }) => {
      const runtimeSafety = new RuntimeSafetyController(
        {},
        { controlStatus: () => session.controlStatus() },
      );
      store.apply({ type: "pause", reason: "operator paused the durable campaign" });
      const beforeRead = store.statistics();

      expect(() => runtimeSafety.assertReady()).toThrow(CampaignPausedError);
      expect(session.state.runtime.control).toBe("paused");
      expect(store.statistics()).toEqual(beforeRead);
    });
  });

  it("keeps a durable pause through history finalization without extra persistence", () => {
    withDurableSession("external-pause-history", ({ session, store }) => {
      store.apply({ type: "pause", reason: "operator pause" });
      const beforeWrite = store.statistics();

      session.finishHistory();

      expectPersistenceDelta(store.statistics(), beforeWrite, {
        records: 2,
        actionRecords: 1,
        checkpointRecords: 1,
        fullStateRecords: 1,
      });
      expectControlAgreement(session.state, store.load("external-pause-history"), {
        control: "paused",
        controlReason: "operator pause",
      });
    });
  });

  it("keeps a durable cancellation through event recording without extra persistence", () => {
    withDurableSession("external-cancel-record", ({ session, store }) => {
      store.apply({ type: "cancel", reason: "operator cancel" });
      const beforeWrite = store.statistics();

      session.record("request", { path: "/after-cancel" });

      expectPersistenceDelta(store.statistics(), beforeWrite, {
        records: 1,
        actionRecords: 1,
        checkpointRecords: 0,
        fullStateRecords: 0,
      });
      expectControlAgreement(session.state, store.load("external-cancel-record"), {
        control: "cancelled",
        controlReason: "operator cancel",
      });
    });
  });

  it("passes an authoritative halt to dispatch callbacks without extra persistence", () => {
    const callbacks: Array<{ state: CampaignState; action?: CampaignAction }> = [];
    withDurableSession(
      "external-halt-dispatch",
      ({ session, store }) => {
        store.apply({ type: "halt", reason: "automatic safety halt" });
        const beforeWrite = store.statistics();

        session.dispatch({ type: "request", phase: "exploration" });

        expectPersistenceDelta(store.statistics(), beforeWrite, {
          records: 2,
          actionRecords: 2,
          checkpointRecords: 0,
          fullStateRecords: 0,
        });
        expect(callbacks).toHaveLength(1);
        expect(callbacks[0]?.action).toEqual({ type: "request", phase: "exploration" });
        expectControlAgreement(callbacks[0]!.state, session.state, {
          control: "halted",
          controlReason: "automatic safety halt",
        });
        expectControlAgreement(session.state, store.load("external-halt-dispatch"), {
          control: "halted",
          controlReason: "automatic safety halt",
        });
      },
      (state, action) => callbacks.push({ state, action }),
    );
  });
});

function withDurableSession(
  campaignId: string,
  run: (context: { session: CampaignSession; store: JsonlCampaignStore }) => void,
  onState?: (state: CampaignState, action?: CampaignAction) => void,
): void {
  const directory = mkdtempSync(join(tmpdir(), "quiver-session-sync-"));
  const store = new JsonlCampaignStore(join(directory, "campaigns.jsonl"));
  try {
    const session = new CampaignSession({
      target: new URL("http://127.0.0.1:8888/"),
      profile: {
        id: campaignId,
        displayName: "External control synchronization",
        objective: "Keep the session synchronized with durable control state.",
      },
      requestBudget: 6,
      explorerCount: 1,
      campaignStore: store,
      onState,
    });
    run({ session, store });
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
}

function expectPersistenceDelta(
  after: ReturnType<JsonlCampaignStore["statistics"]>,
  before: ReturnType<JsonlCampaignStore["statistics"]>,
  delta: Pick<
    ReturnType<JsonlCampaignStore["statistics"]>,
    "records" | "actionRecords" | "checkpointRecords" | "fullStateRecords"
  >,
): void {
  expect(after).toMatchObject({
    durableWrites: before.durableWrites + 1,
    records: before.records + delta.records,
    actionRecords: before.actionRecords + delta.actionRecords,
    checkpointRecords: before.checkpointRecords + delta.checkpointRecords,
    fullStateRecords: before.fullStateRecords + delta.fullStateRecords,
  });
  expect(after.bytes).toBeGreaterThan(before.bytes);
}

function expectControlAgreement(
  actual: CampaignState,
  persisted: CampaignState,
  expected: Pick<CampaignState["runtime"], "control" | "controlReason">,
): void {
  expect(actual.runtime).toMatchObject(expected);
  expect(persisted.runtime).toMatchObject(expected);
}
