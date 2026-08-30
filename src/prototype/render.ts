import type { PrototypeState } from "./state.ts";

const bold = "\x1b[1m";
const dim = "\x1b[2m";
const reset = "\x1b[0m";

export function render(state: PrototypeState): void {
  if (!process.stdout.isTTY) {
    console.log(
      JSON.stringify({
        phase: state.phase,
        requests: `${state.requestsUsed}/${state.requestBudget}`,
        agents: Object.fromEntries(state.agents.map((agent) => [agent.id, agent.status])),
        candidates: state.candidates.map((candidate) => candidate.vehicleId),
        validation: state.validation,
        error: state.error,
      }),
    );
    return;
  }

  console.clear();
  console.log(`${bold}Quiver — crAPI BOLA prototype${reset}`);
  console.log(`${dim}Throwaway logic and orchestration spike${reset}\n`);
  console.log(`${bold}target${reset}      ${state.target}`);
  console.log(`${bold}phase${reset}       ${state.phase}`);
  console.log(`${bold}requests${reset}    ${state.requestsUsed}/${state.requestBudget}`);
  console.log(`${bold}candidates${reset}  ${state.candidates.length}\n`);

  console.log(`${bold}agents${reset}`);
  for (const agent of state.agents) {
    console.log(
      `  ${agent.id.padEnd(12)} ${agent.status}${agent.summary ? ` — ${agent.summary}` : ""}`,
    );
  }

  if (state.candidates.length > 0) {
    console.log(`\n${bold}candidate vehicle IDs${reset}`);
    for (const candidate of state.candidates) console.log(`  ${candidate.vehicleId}`);
  }

  if (state.validation) {
    console.log(`\n${bold}validation${reset}  ${state.validation.status}`);
    console.log(`${dim}${state.validation.evidence}${reset}`);
  }

  if (state.error) console.log(`\n${bold}error${reset} ${state.error}`);
  console.log(`\n${dim}[ctrl-c] stop${reset}`);
}
