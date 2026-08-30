import { init, type ConversationStreamChunk } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { createExplorerAgent, createValidatorAgent } from "./agents.ts";
import { GLM_FLASH_MODEL } from "./models.ts";
import { ScopedTarget } from "./scoped-target.ts";
import {
  createState,
  reduce,
  type Candidate,
  type PrototypeAction,
  type PrototypeState,
} from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";

export type EvalScenario = "discover" | "negative-control";

export interface RunPrototypeOptions {
  target: URL;
  profile: TargetProfile;
  scenario?: EvalScenario;
  requestBudget?: number;
  explorerCount?: number;
  onState?: (state: PrototypeState, action?: PrototypeAction) => void;
}

export interface PrototypeRun {
  scenario: EvalScenario;
  profileId: string;
  model: string;
  durationMs: number;
  state: PrototypeState;
  events: RunEvent[];
}

export interface RunEvent {
  sequence: number;
  elapsedMs: number;
  type: "state" | "request" | "tool-call" | "tool-output" | "tool-error";
  data: Record<string, unknown>;
}

export async function runPrototype(options: RunPrototypeOptions): Promise<PrototypeRun> {
  const startedAt = performance.now();
  const scenario = options.scenario ?? "discover";
  const requestBudget = options.requestBudget ?? 30;
  const explorerCount = scenario === "discover" ? (options.explorerCount ?? 2) : 0;
  const events: RunEvent[] = [];
  const record = (type: RunEvent["type"], data: Record<string, unknown>) => {
    events.push({
      sequence: events.length + 1,
      elapsedMs: Math.round(performance.now() - startedAt),
      type,
      data,
    });
  };
  const captureAgentEvent = (agentId: string, chunk: ConversationStreamChunk) => {
    if (chunk.type === "tool-input") {
      record("tool-call", {
        agentId,
        toolCallId: chunk.toolCallId,
        toolName: chunk.toolName,
        input: chunk.input,
      });
    } else if (chunk.type === "tool-output") {
      record("tool-output", {
        agentId,
        toolCallId: chunk.toolCallId,
        output: chunk.output,
        durationMs: chunk.durationMs,
      });
    } else if (chunk.type === "tool-output-error") {
      record("tool-error", {
        agentId,
        toolCallId: chunk.toolCallId,
        error: chunk.errorText,
        durationMs: chunk.durationMs,
      });
    }
  };
  let state = createState(
    `${options.target.origin}${options.target.pathname}${options.target.search}`,
    requestBudget,
    explorerCount,
  );
  const dispatch = (action: PrototypeAction) => {
    state = reduce(state, action);
    record("state", {
      action: action.type,
      phase: state.phase,
      requestsUsed: state.requestsUsed,
      candidateCount: state.candidates.length,
      validationStatus: state.validation?.status,
    });
    options.onState?.(state, action);
  };
  options.onState?.(state);

  try {
    const target = new ScopedTarget({
      target: options.target,
      requestBudget,
      allowedRequests: options.profile.allowedRequests,
      onRequest: (request) => {
        record("request", { ...request });
        dispatch({ type: "request" });
      },
    });
    let candidates: Candidate[];

    if (scenario === "discover") {
      dispatch({ type: "phase", phase: "exploring" });
      const explorers = Array.from({ length: explorerCount }, (_, index) =>
        createExplorerAgent(`explorer-${index + 1}`, target, options.profile, dispatch),
      );
      {
        await using _explorerRuntime = await start({ agents: explorers });
        await Promise.all(
          explorers.map(async (Explorer, index) => {
            const id = `explorer-${index + 1}`;
            dispatch({ type: "agent", id, status: "running" });
            try {
              const agent = init(Explorer);
              const receipt = await agent.dispatch("Begin the bounded exploration mission.");
              const reply = await agent.read(receipt, {
                onEvent: (chunk) => captureAgentEvent(id, chunk),
              });
              dispatch({
                type: "agent",
                id,
                status: "finished",
                summary: reply.text.slice(0, 100),
              });
            } catch (error) {
              dispatch({ type: "agent", id, status: "failed", summary: String(error) });
            }
          }),
        );
      }
      if (state.candidates.length === 0)
        throw new Error("Explorers produced no evidence-backed candidates");
      candidates = state.candidates;
    } else {
      if (!options.profile.createNegativeControl) {
        throw new Error(`Target profile ${options.profile.id} has no negative control`);
      }
      const candidate = await options.profile.createNegativeControl(target);
      dispatch({ type: "candidate", candidate });
      candidates = [candidate];
    }

    dispatch({ type: "phase", phase: "validating" });
    dispatch({ type: "agent", id: "validator", status: "running" });
    const Validator = createValidatorAgent(candidates, target, options.profile, dispatch);
    {
      await using _validatorRuntime = await start({ agents: [Validator] });
      const validator = init(Validator);
      const receipt = await validator.dispatch("Independently validate the submitted candidates.");
      const reply = await validator.read(receipt, {
        onEvent: (chunk) => captureAgentEvent("validator", chunk),
      });
      dispatch({
        type: "agent",
        id: "validator",
        status: "finished",
        summary: reply.text.slice(0, 100),
      });
    }
    if (!state.validation) throw new Error("Validator did not submit a verdict");
    dispatch({ type: "phase", phase: "complete" });
  } catch (error) {
    dispatch({ type: "failed", error: error instanceof Error ? error.message : String(error) });
  }

  return {
    scenario,
    profileId: options.profile.id,
    model: GLM_FLASH_MODEL,
    durationMs: Math.round(performance.now() - startedAt),
    state,
    events,
  };
}
