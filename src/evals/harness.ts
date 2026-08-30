import { createHarness, type JsonValue } from "vitest-evals";
import { runPrototype, type EvalScenario } from "../prototype/runner.ts";

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
      "candidateVehicleIds",
      run.state.candidates.map((candidate) => candidate.vehicleId),
    );
    setArtifact("transitions", transitions);

    return {
      output,
      events: [
        { type: "message", role: "user", content: JSON.stringify(input) },
        { type: "message", role: "assistant", content: output },
      ],
      usage: { model: run.model, provider: "openrouter" },
    };
  },
});
