import { createHarness, toJsonValue, type JsonValue, type TranscriptEvent } from "vitest-evals";
import { runCampaign } from "../prototype/runner.ts";
import { crapiProfile } from "../targets/crapi.ts";

export interface SecurityEvalInput {
  target: string;
  requestBudget: number;
  explorerCount?: number;
}

export interface SecurityEvalOutput extends Record<string, JsonValue> {
  model: string;
  phase: string;
  findingCount: number;
  confirmedCount: number;
  rejectedCount: number;
  unvalidatedCount: number;
  confirmedFingerprints: string[];
  requestsUsed: number;
  requestBudget: number;
  explorationRequests: number;
  validationRequests: number;
  agentFailures: number;
  durationMs: number;
  error: string | null;
}

export const securityHarness = createHarness<SecurityEvalInput, SecurityEvalOutput>({
  name: "bounded-read-only-security-campaign",
  run: async ({ input, setArtifact }) => {
    const transitions: string[] = [];
    const run = await runCampaign({
      target: new URL(input.target),
      profile: crapiProfile,
      requestBudget: input.requestBudget,
      explorerCount: input.explorerCount,
      onState: (_state, action) => {
        if (action) transitions.push(action.type);
      },
    });
    const confirmedFingerprints = run.state.validations
      .filter((validation) => validation.status === "confirmed")
      .map((validation) => validation.fingerprint);
    const rejectedCount = run.state.validations.filter(
      (validation) => validation.status === "rejected",
    ).length;
    const output: SecurityEvalOutput = {
      model: run.model,
      phase: run.state.phase,
      findingCount: run.state.findings.length,
      confirmedCount: confirmedFingerprints.length,
      rejectedCount,
      unvalidatedCount: run.state.findings.length - run.state.validations.length,
      confirmedFingerprints,
      requestsUsed: run.state.requests.total,
      requestBudget: run.state.budget.total,
      explorationRequests: run.state.requests.exploration,
      validationRequests: run.state.requests.validation,
      agentFailures: run.state.agents.filter((agent) => agent.status === "failed").length,
      durationMs: run.durationMs,
      error: run.state.error ?? null,
    };

    setArtifact("findings", toJsonValue(run.state.findings) ?? []);
    setArtifact("validations", toJsonValue(run.state.validations) ?? []);
    setArtifact("transitions", transitions);
    setArtifact("runTrace", toJsonValue(run.events) ?? []);

    const toolNames = new Map<string, string>();
    const toolEvents: TranscriptEvent[] = [];
    for (const event of run.events) {
      const toolCallId = event.data.toolCallId;
      if (typeof toolCallId !== "string") continue;
      if (event.type === "tool-call") {
        const toolName = event.data.toolName;
        if (typeof toolName !== "string") continue;
        toolNames.set(toolCallId, toolName);
        const inputValue = toJsonValue(event.data.input);
        toolEvents.push({
          type: "tool_call",
          id: toolCallId,
          name: toolName,
          arguments:
            inputValue && typeof inputValue === "object" && !Array.isArray(inputValue)
              ? inputValue
              : { value: inputValue ?? null },
          metadata: { agentId: String(event.data.agentId) },
        });
      } else if (event.type === "tool-output") {
        toolEvents.push({
          type: "tool_result",
          toolCallId,
          name: toolNames.get(toolCallId),
          content: toJsonValue(event.data.output),
          durationMs: typeof event.data.durationMs === "number" ? event.data.durationMs : undefined,
          metadata: { agentId: String(event.data.agentId) },
        });
      } else if (event.type === "tool-error") {
        toolEvents.push({
          type: "tool_result",
          toolCallId,
          name: toolNames.get(toolCallId),
          error: { name: "ToolError", message: String(event.data.error) },
          durationMs: typeof event.data.durationMs === "number" ? event.data.durationMs : undefined,
          metadata: { agentId: String(event.data.agentId) },
        });
      }
    }

    return {
      output,
      events: [
        { type: "message", role: "user", content: JSON.stringify(input) },
        ...toolEvents,
        { type: "message", role: "assistant", content: output },
      ],
      usage: { model: run.model, provider: "openrouter" },
    };
  },
});
