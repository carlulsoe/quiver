import type { ConversationStreamChunk } from "@flue/runtime";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CampaignSession, type CampaignSessionOptions } from "./campaign-session.ts";
import { JsonlCampaignStore } from "./campaign-store.ts";
import { CampaignPausedError, RuntimeSafetyController } from "./runtime-safety.ts";

describe("campaign session", () => {
  it("redacts tool inputs and omits tool results before persisting history", () => {
    const options: CampaignSessionOptions = {
      target: new URL("http://127.0.0.1:8888/"),
      profile: {
        id: "history-redaction",
        displayName: "History redaction",
        objective: "Never persist raw tool credentials or results.",
      },
      requestBudget: 6,
      explorerCount: 1,
    };
    const session = new CampaignSession(options);
    session.captureAgentEvent(
      "explorer-1",
      chunk({
        type: "tool-input",
        conversationId: "conversation",
        messageId: "message",
        toolCallId: "call-1",
        toolName: "request_rest",
        input: {
          fingerprint: "other:GET:/authors",
          headers: { xapikey: "input-secret", "x-author": "Ada" },
          body: '{"password":"body-secret","author":"Ada"}',
        },
      }),
    );
    session.captureAgentEvent(
      "explorer-1",
      chunk({
        type: "tool-output",
        conversationId: "conversation",
        toolCallId: "call-1",
        output: { authorization: "output-secret", body: { private: "target-data" } },
      }),
    );
    session.captureAgentEvent(
      "explorer-1",
      chunk({
        type: "tool-output-error",
        conversationId: "conversation",
        toolCallId: "call-2",
        errorText: "Bearer error-secret",
      }),
    );
    session.record("request", { path: "/authors?token=request-secret" });

    const persisted = JSON.stringify(session.state.history.events);
    expect(persisted).not.toContain("input-secret");
    expect(persisted).not.toContain("body-secret");
    expect(persisted).not.toContain("output-secret");
    expect(persisted).not.toContain("target-data");
    expect(persisted).not.toContain("error-secret");
    expect(persisted).not.toContain("request-secret");
    expect(persisted).toContain("other:GET:/authors");
    expect(persisted).toContain("Ada");
  });

  it("reads externally persisted control state without writing or checkpointing", () => {
    const directory = mkdtempSync(join(tmpdir(), "quiver-session-control-"));
    const store = new JsonlCampaignStore(join(directory, "campaigns.jsonl"));
    try {
      const session = new CampaignSession({
        target: new URL("http://127.0.0.1:8888/"),
        profile: {
          id: "external-control",
          displayName: "External control",
          objective: "Observe authoritative durable control state.",
        },
        requestBudget: 6,
        explorerCount: 1,
        campaignStore: store,
      });
      const runtimeSafety = new RuntimeSafetyController(
        {},
        { controlStatus: () => session.controlStatus() },
      );
      store.apply({ type: "pause", reason: "operator paused the durable campaign" });
      const beforeRead = store.statistics();

      expect(() => runtimeSafety.assertReady()).toThrow(CampaignPausedError);
      expect(store.statistics()).toEqual(beforeRead);
    } finally {
      store.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

type ToolChunk = Extract<
  ConversationStreamChunk,
  { type: "tool-input" | "tool-output" | "tool-output-error" }
>;
type WithoutPosition<Chunk> = Chunk extends ToolChunk ? Omit<Chunk, "position"> : never;

function chunk(value: WithoutPosition<ToolChunk>): ConversationStreamChunk {
  return { ...value, position: { batch: 0, index: 0 } };
}
