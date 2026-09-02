import type { CoordinatorSnapshot } from "./adaptive-coordinator.ts";
import { emptyCampaignHistory } from "./campaign-history.ts";
import type { CampaignBudget, CampaignIdentity, CampaignState } from "./state-types.ts";

export function createCampaignBudget(total: number): CampaignBudget {
  if (!Number.isInteger(total) || total < 3) {
    throw new Error("Campaign request budget must be an integer of at least 3");
  }
  const validation = Math.ceil(total / 3);
  return { total, exploration: total - validation, validation };
}

export function createCampaignState(
  target: string,
  budget: CampaignBudget,
  explorerCount = 2,
  identity?: CampaignIdentity,
): CampaignState {
  if (budget.exploration + budget.validation !== budget.total) {
    throw new Error("Exploration and validation budgets must equal the total budget");
  }
  const state: CampaignState = {
    target,
    phase: "starting",
    budget,
    requests: { total: 0, exploration: 0, validation: 0 },
    agents: [
      ...Array.from({ length: explorerCount }, (_, index) => ({
        id: `explorer-${index + 1}`,
        role: "explorer" as const,
        status: "queued" as const,
      })),
      { id: "validator", role: "validator", status: "queued" },
    ],
    testedRequests: [],
    discoveredRoutes: [],
    discoveredOperations: [],
    findings: [],
    validations: [],
    coordination: emptyCoordinatorSnapshot(budget.exploration),
    exploitChains: [],
    exploitChainValidations: [],
    runtime: { control: "running", consecutiveFailures: 0, disruptiveResponses: 0, jobs: [] },
    history: emptyCampaignHistory(),
  };
  if (identity) state.identity = identity;
  return state;
}

function emptyCoordinatorSnapshot(requestBudget: number): CoordinatorSnapshot {
  return {
    revision: 0,
    coverage: {
      discoveredOperations: 0,
      testedOperations: 0,
      operationCoverage: 0,
      testedAccessModes: 0,
      totalAccessModes: 0,
      accessModeCoverage: 0,
    },
    hypotheses: [],
    debriefs: [],
    specialists: [],
    validationQueue: [],
    budget: {
      total: requestBudget,
      consumed: 0,
      allocated: 0,
      available: requestBudget,
      workers: {},
    },
  };
}
