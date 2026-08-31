import { campaignOperationCoverage, type CampaignAction, type CampaignState } from "./state.ts";

const bold = "\x1b[1m";
const dim = "\x1b[2m";
const reset = "\x1b[0m";

export function render(state: CampaignState, action?: CampaignAction): void {
  const confirmed = state.validations.filter(
    (validation) => validation.status === "confirmed",
  ).length;
  const rejected = state.validations.filter(
    (validation) => validation.status === "rejected",
  ).length;
  const unvalidated = state.findings.length - state.validations.length;
  const operationCoverage = campaignOperationCoverage(state);

  if (!process.stdout.isTTY) {
    console.log(
      JSON.stringify({
        phase: state.phase,
        requests: state.requests,
        budget: state.budget,
        agents: Object.fromEntries(state.agents.map((agent) => [agent.id, agent.status])),
        findings: { total: state.findings.length, confirmed, rejected, unvalidated },
        operationCoverage,
        coordination: {
          accessModeCoverage: state.coordination.coverage.accessModeCoverage,
          hypotheses: state.coordination.hypotheses.length,
          specialists: state.coordination.specialists.length,
          pendingValidation: state.coordination.validationQueue.filter(
            ({ status }) => status !== "complete",
          ).length,
        },
        transition: action?.type,
        error: state.error,
      }),
    );
    return;
  }

  console.clear();
  console.log(`${bold}Quiver — bounded REST pentest campaign${reset}`);
  console.log(`${dim}Target-guided discovery and independent replay${reset}\n`);
  console.log(
    `${bold}flow${reset}        ${flowStep("map", state.phase !== "starting")} → ${flowStep("hypothesize", state.findings.length > 0)} → ${flowStep("exploit", state.testedRequests.length > 0)} → ${flowStep("prove", state.validations.length > 0)}`,
  );
  console.log(`${bold}target${reset}      ${state.target}`);
  console.log(`${bold}phase${reset}       ${state.phase}`);
  console.log(
    `${bold}requests${reset}    ${state.requests.total}/${state.budget.total} ` +
      `(explore ${state.requests.exploration}/${state.budget.exploration}, ` +
      `validate ${state.requests.validation}/${state.budget.validation})`,
  );
  console.log(
    `${bold}coverage${reset}    ${(operationCoverage.coverage * 100).toFixed(0)}% actionable operations ` +
      `(${operationCoverage.tested}/${operationCoverage.discovered}), ` +
      `${(state.coordination.coverage.accessModeCoverage * 100).toFixed(0)}% access modes`,
  );
  console.log(
    `${bold}findings${reset}    ${state.findings.length} ` +
      `(confirmed ${confirmed}, rejected ${rejected}, unvalidated ${unvalidated})\n`,
  );

  console.log(`${bold}agents${reset}`);
  for (const agent of state.agents) {
    console.log(
      `  ${agent.id.padEnd(12)} ${agent.status}${agent.summary ? ` — ${agent.summary}` : ""}`,
    );
  }

  console.log(
    `\n${bold}coordinator${reset} ${state.coordination.hypotheses.length} hypotheses, ` +
      `${state.coordination.specialists.length} specialists, ` +
      `${state.coordination.validationQueue.filter(({ status }) => status !== "complete").length} validations pending`,
  );

  if (state.findings.length > 0) {
    console.log(`\n${bold}findings${reset}`);
    for (const finding of state.findings) {
      const status =
        state.validations.find((validation) => validation.fingerprint === finding.fingerprint)
          ?.status ?? "unvalidated";
      console.log(`  [${status}] ${finding.title}`);
      console.log(`${dim}    ${finding.fingerprint}${reset}`);
      const validation = state.validations.find((item) => item.fingerprint === finding.fingerprint);
      if (validation) {
        console.log(
          `${dim}    ${validation.proof.predicate}: ${validation.proof.checks.filter(({ passed }) => passed).length}/${validation.proof.checks.length} checks${reset}`,
        );
      }
    }
  }

  if (state.testedRequests.length > 0) {
    console.log(`\n${bold}recent requests${reset}`);
    for (const request of state.testedRequests.slice(-5)) {
      console.log(
        `  ${String(request.status).padEnd(3)} ${request.authenticated ? "auth" : "anon"} ${request.method ?? "GET"} ${request.path}`,
      );
    }
  }

  if (state.error) console.log(`\n${bold}error${reset} ${state.error}`);
  if (action) console.log(`\n${dim}transition: ${action.type}${reset}`);
  console.log(`\n${dim}[ctrl-c] stop${reset}`);
}

function flowStep(label: string, complete: boolean): string {
  return complete ? `${label} ✓` : label;
}
