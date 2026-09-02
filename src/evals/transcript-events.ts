import { toJsonValue, type JsonValue, type TranscriptEvent } from "vitest-evals";
import type { CampaignRun } from "../prototype/runner.ts";

export function transcriptEvents(run: CampaignRun): TranscriptEvent[] {
  const toolNames = new Map<string, string>();
  const events: TranscriptEvent[] = [];
  for (const event of run.events) {
    const toolCallId = parseString(event.data.toolCallId);
    if (!toolCallId) continue;
    if (event.type === "tool-call") {
      const toolName = parseString(event.data.toolName);
      if (!toolName) continue;
      toolNames.set(toolCallId, toolName);
      const inputValue = toJsonValue(event.data.input);
      events.push({
        type: "tool_call",
        id: toolCallId,
        name: toolName,
        arguments: jsonObject(inputValue),
        metadata: { agentId: String(event.data.agentId) },
      });
    } else if (event.type === "tool-output") {
      events.push({
        type: "tool_result",
        toolCallId,
        name: toolNames.get(toolCallId),
        content: toJsonValue(event.data.output),
        durationMs: parseNumber(event.data.durationMs),
        metadata: { agentId: String(event.data.agentId) },
      });
    } else if (event.type === "tool-error") {
      events.push({
        type: "tool_result",
        toolCallId,
        name: toolNames.get(toolCallId),
        error: { name: "ToolError", message: String(event.data.error) },
        durationMs: parseNumber(event.data.durationMs),
        metadata: { agentId: String(event.data.agentId) },
      });
    }
  }
  return events;
}

function parseString<T>(value: T): string | undefined {
  return Object.prototype.toString.call(value) === "[object String]" ? String(value) : undefined;
}

function parseNumber<T>(value: T): number | undefined {
  return Object.prototype.toString.call(value) === "[object Number]" ? Number(value) : undefined;
}

function jsonObject(value: JsonValue | undefined): Record<string, JsonValue> {
  return value instanceof Object && !Array.isArray(value) ? value : { value: value ?? null };
}
