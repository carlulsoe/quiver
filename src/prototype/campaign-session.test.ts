import type { ConversationStreamChunk } from "@flue/runtime";
import { describe, expect, it } from "vitest";
import { CampaignSession, type CampaignSessionOptions } from "./campaign-session.ts";

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
});

type ToolChunk = Extract<
  ConversationStreamChunk,
  { type: "tool-input" | "tool-output" | "tool-output-error" }
>;
type WithoutPosition<Chunk> = Chunk extends ToolChunk ? Omit<Chunk, "position"> : never;

function chunk(value: WithoutPosition<ToolChunk>): ConversationStreamChunk {
  return { ...value, position: { batch: 0, index: 0 } };
}
