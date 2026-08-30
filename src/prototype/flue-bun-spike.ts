/**
 * PROTOTYPE: Prove whether Flue's documented Node runtime can complete a real
 * model turn when the host process is Bun.
 */
import { init, useModel } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { GLM_FLASH_MODEL } from "./models.ts";

function BunSmokeAgent() {
  useModel(GLM_FLASH_MODEL, {
    thinkingLevel: "low",
  });

  return "Reply with exactly: FLUE_ON_BUN_OK";
}

BunSmokeAgent.agentName = "bun-smoke-agent";

await using _flue = await start({ agents: [BunSmokeAgent] });
const agent = init(BunSmokeAgent);
const receipt = await agent.dispatch("Run the compatibility check.");
const reply = await agent.read(receipt);

console.log(reply.text);
