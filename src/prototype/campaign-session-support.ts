import { number, object, optional, safeParse, string } from "valibot";
import type { ConversationStreamChunk } from "@flue/runtime";
import type { RunEvent, RunEventData } from "./campaign-history.ts";
import { redactCredentials } from "./security/redaction.ts";
import type { CampaignState } from "./state.ts";

const promptUsageSchema = object({
  input: number(),
  output: number(),
  cacheRead: number(),
  cacheWrite: number(),
  totalTokens: number(),
  cost: object({
    input: number(),
    output: number(),
    cacheRead: number(),
    cacheWrite: number(),
    total: number(),
  }),
});
const promptMetadataSchema = object({
  quiverUsage: promptUsageSchema,
  quiverModel: optional(string()),
});

export function parsePromptMetadata<Metadata>(metadata: Metadata) {
  const parsed = safeParse(promptMetadataSchema, metadata);
  return parsed.success ? parsed.output : undefined;
}
function durableToolInput<Input>(input: Input): object | string {
  return input instanceof Object
    ? redactCredentials(input)
    : "[tool input omitted from durable history]";
}
export function agentStreamEvent(
  agentId: string,
  chunk: ConversationStreamChunk,
): { type: RunEvent["type"]; data: RunEventData } | undefined {
  if (chunk.type === "tool-input")
    return {
      type: "tool-call",
      data: {
        agentId,
        toolCallId: chunk.toolCallId,
        toolName: chunk.toolName,
        input: durableToolInput(chunk.input),
      },
    };
  if (chunk.type === "tool-output")
    return {
      type: "tool-output",
      data: {
        agentId,
        toolCallId: chunk.toolCallId,
        output: "[tool output omitted from durable history]",
        durationMs: chunk.durationMs,
      },
    };
  if (chunk.type === "tool-output-error")
    return {
      type: "tool-error",
      data: {
        agentId,
        toolCallId: chunk.toolCallId,
        error: "[tool error detail omitted from durable history]",
        durationMs: chunk.durationMs,
      },
    };
  return undefined;
}
export function createRunEvent(
  previousSequence: number,
  elapsedMs: number,
  type: RunEvent["type"],
  data: RunEventData,
): RunEvent {
  return {
    sequence: previousSequence + 1,
    elapsedMs,
    type,
    data: redactCredentials(data),
  };
}
export function assertCampaignTarget(state: CampaignState, campaignId: string, target: URL): void {
  const expected = `${target.origin}${target.pathname}${target.search}`;
  if (state.target !== expected)
    throw new Error(`Campaign ${campaignId} targets ${state.target}, not ${expected}`);
}
