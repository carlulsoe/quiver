import type { CampaignAction } from "./state-actions.ts";
import {
  campaignJob,
  completeJob,
  exploitChainJobId,
  fingerprintExploitChain,
  fingerprintFinding,
  normalizeFindingInput,
  operationKey,
  validationJobId,
  withRuntimeState,
} from "./state-helpers.ts";
import { reduceRuntimeAction } from "./state-runtime-reducer.ts";
import type { CampaignState } from "./state-types.ts";

const nextPhases = {
  starting: ["exploring", "failed"],
  exploring: ["validating", "failed"],
  validating: ["complete", "failed"],
  complete: [],
  failed: [],
} satisfies Record<CampaignState["phase"], CampaignState["phase"][]>;

export function reduceCampaign(input: CampaignState, action: CampaignAction): CampaignState {
  const state = withRuntimeState(input);
  const runtimeResult = reduceRuntimeAction(state, action);
  if (runtimeResult) return runtimeResult;
  if (state.phase === "complete" || state.phase === "failed") return state;
  switch (action.type) {
    case "phase":
      return action.phase !== state.phase &&
        nextPhases[state.phase].some((phase) => phase === action.phase)
        ? { ...state, phase: action.phase }
        : state;
    case "request":
      return {
        ...state,
        requests: {
          total: state.requests.total + 1,
          exploration: state.requests.exploration + (action.phase === "exploration" ? 1 : 0),
          validation: state.requests.validation + (action.phase === "validation" ? 1 : 0),
        },
      };
    case "reclaim-exploration-budget":
      return reclaimExplorationBudget(state);
    case "agent":
      return {
        ...state,
        agents: state.agents.map((agent) =>
          agent.id === action.id
            ? { ...agent, status: action.status, summary: action.summary ?? agent.summary }
            : agent,
        ),
      };
    case "agent-spawned":
      return state.agents.some(({ id }) => id === action.id)
        ? state
        : {
            ...state,
            agents: [...state.agents, { id: action.id, role: action.role, status: "queued" }],
          };
    case "coordinator-snapshot":
      return { ...state, coordination: action.snapshot };
    case "request-tested":
      return { ...state, testedRequests: [...state.testedRequests, action.request] };
    case "routes-discovered":
      return {
        ...state,
        discoveredRoutes: [...new Set([...state.discoveredRoutes, ...action.routes])],
      };
    case "operations-discovered": {
      const operations = new Map(
        [...state.discoveredOperations, ...action.operations].map((operation) => [
          operationKey(operation),
          operation,
        ]),
      );
      return { ...state, discoveredOperations: [...operations.values()] };
    }
    case "finding":
      return addFinding(state, action.finding);
    case "validation":
      if (
        state.validations.some(({ fingerprint }) => fingerprint === action.validation.fingerprint)
      )
        return state;
      return {
        ...state,
        validations: [...state.validations, action.validation],
        runtime: completeJob(state.runtime, validationJobId(action.validation.fingerprint)),
      };
    case "exploit-chain":
      return addExploitChain(state, action.chain);
    case "exploit-chain-validation":
      if (
        state.exploitChainValidations.some(
          ({ fingerprint }) => fingerprint === action.validation.fingerprint,
        )
      )
        return state;
      return {
        ...state,
        exploitChainValidations: [...state.exploitChainValidations, action.validation],
        runtime: completeJob(state.runtime, exploitChainJobId(action.validation.fingerprint)),
      };
    case "failed":
      return { ...state, phase: "failed", error: action.error };
    default:
      return state;
  }
}

function reclaimExplorationBudget(state: CampaignState): CampaignState {
  const unused = Math.max(0, state.budget.exploration - state.requests.exploration);
  if (unused === 0) return state;
  return {
    ...state,
    budget: {
      total: state.budget.total,
      exploration: state.budget.exploration - unused,
      validation: state.budget.validation + unused,
    },
  };
}

function addFinding(
  state: CampaignState,
  input: Extract<CampaignAction, { type: "finding" }>["finding"],
): CampaignState {
  const normalized = normalizeFindingInput(input);
  const finding = { ...normalized, fingerprint: fingerprintFinding(normalized) };
  if (state.findings.some(({ fingerprint }) => fingerprint === finding.fingerprint)) return state;
  return {
    ...state,
    findings: [...state.findings, finding],
    runtime: {
      ...state.runtime,
      jobs: [
        ...state.runtime.jobs,
        campaignJob("validation", finding.fingerprint, finding.impactLevel),
      ],
    },
  };
}

function addExploitChain(
  state: CampaignState,
  input: Extract<CampaignAction, { type: "exploit-chain" }>["chain"],
): CampaignState {
  const chain = { ...input, fingerprint: fingerprintExploitChain(input) };
  if (state.exploitChains.some(({ fingerprint }) => fingerprint === chain.fingerprint))
    return state;
  return {
    ...state,
    exploitChains: [...state.exploitChains, chain],
    runtime: {
      ...state.runtime,
      jobs: [
        ...state.runtime.jobs,
        campaignJob("exploit-chain", chain.fingerprint, chain.impactLevel),
      ],
    },
  };
}
