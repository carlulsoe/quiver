import { aggregateMissionUsage } from "./campaign-history.ts";
import type { RuntimeReducerAction } from "./state-actions.ts";
import type { CampaignJob, CampaignState } from "./state-types.ts";

export function reduceRuntimeAction(
  state: CampaignState,
  action: RuntimeReducerAction,
): CampaignState {
  switch (action.type) {
    case "run-event":
      return {
        ...state,
        history: {
          ...state.history,
          durationMs: Math.max(state.history.durationMs, action.event.elapsedMs),
          events: [...state.history.events, structuredClone(action.event)],
        },
      };
    case "mission-started": {
      const missionUsage = [...state.history.missionUsage, structuredClone(action.mission)];
      return {
        ...state,
        history: { ...state.history, missionUsage, usage: aggregateMissionUsage(missionUsage) },
      };
    }
    case "mission-updated": {
      if (!state.history.missionUsage[action.index]) return state;
      const missionUsage = state.history.missionUsage.map((mission, index) =>
        index === action.index ? structuredClone(action.mission) : mission,
      );
      return {
        ...state,
        history: { ...state.history, missionUsage, usage: aggregateMissionUsage(missionUsage) },
      };
    }
    case "history-elapsed":
      return {
        ...state,
        history: {
          ...state.history,
          durationMs: Math.max(state.history.durationMs, action.durationMs),
        },
      };
    case "pause":
      if (state.runtime.control !== "running") return state;
      return {
        ...state,
        runtime: { ...state.runtime, control: "paused", controlReason: action.reason },
      };
    case "resume":
      if (state.runtime.control !== "paused") return state;
      return {
        ...state,
        runtime: { ...state.runtime, control: "running", controlReason: undefined },
      };
    case "cancel":
      if (["cancelled", "halted"].includes(state.runtime.control)) return state;
      return {
        ...state,
        runtime: { ...state.runtime, control: "cancelled", controlReason: action.reason },
      };
    case "halt":
      if (state.runtime.control === "cancelled") return state;
      return {
        ...state,
        runtime: { ...state.runtime, control: "halted", controlReason: action.reason },
      };
    case "recover":
      return recoverCampaign(state);
    case "job-started":
      return {
        ...state,
        runtime: {
          ...state.runtime,
          jobs: state.runtime.jobs.map((job) =>
            canStart(job, action.id)
              ? {
                  ...job,
                  status: "running",
                  attempts: job.attempts + 1,
                  mutationStarted: false,
                  error: undefined,
                }
              : job,
          ),
        },
      };
    case "job-mutation-started":
      return {
        ...state,
        runtime: {
          ...state.runtime,
          jobs: state.runtime.jobs.map((job) =>
            job.id === action.id && job.status === "running" && job.impactLevel === "state-change"
              ? { ...job, mutationStarted: true }
              : job,
          ),
        },
      };
    case "job-failed":
      return failJob(state, action.id, action.error, action.retryable);
    case "runtime-success":
      return state.runtime.consecutiveFailures === 0
        ? state
        : { ...state, runtime: { ...state.runtime, consecutiveFailures: 0 } };
    case "runtime-failure":
      return {
        ...state,
        runtime: {
          ...state.runtime,
          consecutiveFailures: state.runtime.consecutiveFailures + 1,
          disruptiveResponses: state.runtime.disruptiveResponses + (action.disruptive ? 1 : 0),
        },
      };
  }
  return unhandledRuntimeAction(action);
}

function unhandledRuntimeAction(action: never): never {
  throw new Error(`Unhandled runtime action: ${JSON.stringify(action)}`);
}

function recoverCampaign(state: CampaignState): CampaignState {
  let interrupted = false;
  const jobs = state.runtime.jobs.map((job): CampaignJob => {
    if (job.status !== "running") return job;
    if (job.impactLevel === "state-change" && job.mutationStarted) {
      interrupted = true;
      return {
        ...job,
        status: "interrupted",
        error: "Process exited while a state-changing proof attempt was in flight",
      };
    }
    return { ...job, status: "queued", mutationStarted: false, error: undefined };
  });
  const runtime = { ...state.runtime, jobs };
  if (interrupted) {
    runtime.control = "halted";
    runtime.controlReason =
      "A state-changing proof attempt was interrupted; manual target review is required";
  }
  return {
    ...state,
    agents: state.agents.map((agent) =>
      agent.status === "running" ? { ...agent, status: "queued" } : agent,
    ),
    runtime,
  };
}

function canStart(job: CampaignJob, id: string): boolean {
  return (
    job.id === id &&
    (job.status === "queued" || (job.status === "failed" && job.impactLevel !== "state-change"))
  );
}

function failJob(
  state: CampaignState,
  id: string,
  error: string,
  retryable: boolean,
): CampaignState {
  let interrupted = false;
  const jobs = state.runtime.jobs.map((job): CampaignJob => {
    if (job.id !== id || job.status !== "running") return job;
    if (job.impactLevel === "state-change" && job.mutationStarted) {
      interrupted = true;
      return { ...job, status: "interrupted", error };
    }
    return { ...job, status: retryable ? "queued" : "failed", mutationStarted: false, error };
  });
  const runtime = { ...state.runtime, jobs };
  if (interrupted && state.runtime.control !== "cancelled") {
    runtime.control = "halted";
    runtime.controlReason =
      "A state-changing proof attempt was interrupted; manual target review is required";
  }
  return { ...state, runtime };
}
