import { createHarness, toJsonValue, type JsonValue, type TranscriptEvent } from "vitest-evals";
import { runPrototype, type EvalScenario } from "../prototype/runner.ts";
import { crapiProfile } from "../targets/crapi.ts";

export interface SecurityEvalInput {
  scenario: EvalScenario;
  target: string;
  requestBudget: number;
  explorerCount?: number;
}

export interface SecurityEvalOutput extends Record<string, JsonValue> {
  scenario: EvalScenario;
  model: string;
  phase: string;
  validationStatus: string | null;
  evidence: string | null;
  candidateCount: number;
  requestsUsed: number;
  requestBudget: number;
  agentFailures: number;
  durationMs: number;
}

export const securityHarness = createHarness<SecurityEvalInput, SecurityEvalOutput>({
  name: "bounded-crapi-security-agent",
  run: async ({ input, setArtifact }) => {
    const transitions: string[] = [];
    const run = await runPrototype({
      target: new URL(input.target),
      profile: crapiProfile,
      scenario: input.scenario,
      requestBudget: input.requestBudget,
      explorerCount: input.explorerCount,
      onState: (_state, action) => {
        if (action) transitions.push(action.type);
      },
    });
    const output: SecurityEvalOutput = {
      scenario: run.scenario,
      model: run.model,
      phase: run.state.phase,
      validationStatus: run.state.validation?.status ?? null,
      evidence: run.state.validation?.evidence ?? run.state.error ?? null,
      candidateCount: run.state.candidates.length,
      requestsUsed: run.state.requestsUsed,
      requestBudget: run.state.requestBudget,
      agentFailures: run.state.agents.filter((agent) => agent.status === "failed").length,
      durationMs: run.durationMs,
    };

    setArtifact(
      "candidateResources",
      run.state.candidates.map((candidate) => candidate.resource),
    );
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
        const input = toJsonValue(event.data.input);
        toolEvents.push({
          type: "tool_call",
          id: toolCallId,
          name: toolName,
          arguments:
            input && typeof input === "object" && !Array.isArray(input)
              ? input
              : { value: input ?? null },
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
