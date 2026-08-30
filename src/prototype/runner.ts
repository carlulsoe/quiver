/**
 * PROTOTYPE QUESTION
 * Can a bounded Flue discovery loop reliably confirm a real crAPI BOLA while
 * rejecting an authenticated user's own vehicle as a negative control?
 */
import { init } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { createExplorerAgent, createValidatorAgent, selectedModel } from "./agents.ts";
import { LocalCrapiGateway } from "./gateway.ts";
import {
  createState,
  reduce,
  type Candidate,
  type PrototypeAction,
  type PrototypeState,
} from "./state.ts";

export type EvalScenario = "discover" | "safe-control";

export interface RunPrototypeOptions {
  target: URL;
  scenario?: EvalScenario;
  requestBudget?: number;
  explorerCount?: number;
  onState?: (state: PrototypeState, action?: PrototypeAction) => void;
}

export interface PrototypeRun {
  scenario: EvalScenario;
  model: string;
  durationMs: number;
  state: PrototypeState;
}

const localHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);

function assertLocalTarget(target: URL): void {
  if (!localHosts.has(target.hostname) || !["http:", "https:"].includes(target.protocol)) {
    throw new Error("This prototype only accepts loopback HTTP(S) targets");
  }
}

export async function runPrototype(options: RunPrototypeOptions): Promise<PrototypeRun> {
  const startedAt = performance.now();
  const scenario = options.scenario ?? "discover";
  const requestBudget = options.requestBudget ?? 30;
  const explorerCount = scenario === "discover" ? (options.explorerCount ?? 2) : 0;
  assertLocalTarget(options.target);

  let state = createState(options.target.origin, requestBudget, explorerCount);
  const dispatch = (action: PrototypeAction) => {
    state = reduce(state, action);
    options.onState?.(state, action);
  };
  options.onState?.(state);
  const gateway = new LocalCrapiGateway(options.target, requestBudget, dispatch);

  try {
    await gateway.healthcheck();
    let candidates: Candidate[];

    if (scenario === "discover") {
      dispatch({ type: "phase", phase: "exploring" });
      const explorers = Array.from({ length: explorerCount }, (_, index) =>
        createExplorerAgent(`explorer-${index + 1}`, gateway, dispatch),
      );

      {
        await using _explorerRuntime = await start({ agents: explorers });
        await Promise.all(
          explorers.map(async (Explorer, index) => {
            const id = `explorer-${index + 1}`;
            dispatch({ type: "agent", id, status: "running" });
            try {
              const agent = init(Explorer);
              const receipt = await agent.dispatch("Begin the bounded BOLA exploration mission.");
              const reply = await agent.read(receipt);
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

      if (state.candidates.length === 0) {
        throw new Error("Explorers produced no evidence-backed candidates");
      }
      candidates = state.candidates;
    } else {
      const vehicleId = await gateway.getOwnVehicleId();
      const safeCandidate: Candidate = {
        agentId: "negative-control",
        vehicleId,
        sourcePath: "/identity/api/v2/vehicle/vehicles",
        locationPath: `/identity/api/v2/vehicle/${vehicleId}/location`,
        rationale: "Negative control: this vehicle belongs to the authenticated user.",
      };
      dispatch({ type: "candidate", candidate: safeCandidate });
      candidates = [safeCandidate];
    }

    dispatch({ type: "phase", phase: "validating" });
    dispatch({ type: "agent", id: "validator", status: "running" });
    const Validator = createValidatorAgent(candidates, gateway, dispatch);
    await using _validatorRuntime = await start({ agents: [Validator] });
    const validator = init(Validator);
    const receipt = await validator.dispatch("Independently validate the submitted candidates.");
    const reply = await validator.read(receipt);
    dispatch({
      type: "agent",
      id: "validator",
      status: "finished",
      summary: reply.text.slice(0, 100),
    });

    if (!state.validation) throw new Error("Validator did not submit a verdict");
    dispatch({ type: "phase", phase: "complete" });
  } catch (error) {
    dispatch({ type: "failed", error: error instanceof Error ? error.message : String(error) });
  }

  return {
    scenario,
    model: selectedModel(),
    durationMs: Math.round(performance.now() - startedAt),
    state,
  };
}
