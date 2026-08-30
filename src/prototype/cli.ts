#!/usr/bin/env bun
/**
 * PROTOTYPE QUESTION
 * Can two short-lived Flue explorers plus a fresh validator prove crAPI's
 * vehicle-location BOLA through a Bun CLI with hard scope and request bounds?
 */
import { init } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { createExplorerAgent, createValidatorAgent } from "./agents.ts";
import { LocalCrapiGateway } from "./gateway.ts";
import { render } from "./render.ts";
import { createState, reduce, type PrototypeAction } from "./state.ts";

const target = new URL(process.argv[2] ?? "http://127.0.0.1:8888");
const localHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
if (!localHosts.has(target.hostname) || !["http:", "https:"].includes(target.protocol)) {
  throw new Error("This prototype only accepts loopback HTTP(S) targets");
}

const requestBudget = 30;
let state = createState(target.origin, requestBudget);
const dispatch = (action: PrototypeAction) => {
  state = reduce(state, action);
  render(state);
};

render(state);
const gateway = new LocalCrapiGateway(target, requestBudget, dispatch);

try {
  await gateway.healthcheck();
  dispatch({ type: "phase", phase: "exploring" });

  const explorers = [
    createExplorerAgent("explorer-1", gateway, dispatch),
    createExplorerAgent("explorer-2", gateway, dispatch),
  ];
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
          dispatch({ type: "agent", id, status: "finished", summary: reply.text.slice(0, 100) });
        } catch (error) {
          dispatch({ type: "agent", id, status: "failed", summary: String(error) });
        }
      }),
    );
  }

  if (state.candidates.length === 0)
    throw new Error("Explorers produced no evidence-backed candidates");

  dispatch({ type: "phase", phase: "validating" });
  dispatch({ type: "agent", id: "validator", status: "running" });
  const Validator = createValidatorAgent(state.candidates, gateway, dispatch);
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
  if (state.validation.status !== "confirmed") process.exitCode = 2;
} catch (error) {
  dispatch({ type: "failed", error: error instanceof Error ? error.message : String(error) });
  process.exitCode = 1;
}
