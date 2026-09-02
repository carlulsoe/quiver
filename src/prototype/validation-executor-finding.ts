import { init } from "@flue/runtime";
import { createValidatorAgent } from "./agents.ts";
import { estimateTokens, validationRequirements } from "./model-routing.ts";
import type { RoutedMission } from "./mission-runtime.ts";
import { isRequestBudgetExhausted, isRuntimeStopError } from "./runner-errors.ts";
import { validationJobId } from "./state.ts";
import type { ValidationExecutorOptions } from "./validation-executor-types.ts";

interface ValidationMissionContext {
  options: ValidationExecutorOptions;
  cursor: RoutedMission;
  agentDefinition: ReturnType<typeof createValidatorAgent>;
  missionIndex: number;
  advanceMissionIndex: () => void;
  setActiveJobId: (jobId: string | undefined) => void;
}

export async function executeValidationFinding(
  context: ValidationMissionContext,
  fingerprint: string,
  finalAttempt: boolean,
): Promise<void> {
  const { session, coordinator, modelRouter } = context.options;
  if (session.state.validations.some((item) => item.fingerprint === fingerprint)) return;
  const finding = session.state.findings.find((item) => item.fingerprint === fingerprint);
  if (!finding) return;
  const jobId = validationJobId(fingerprint);
  if (session.state.runtime.jobs.find(({ id }) => id === jobId)?.status !== "queued") return;
  const validatorId =
    context.missionIndex === 0 ? "validator" : `validator-${context.missionIndex + 1}`;
  context.advanceMissionIndex();
  if (!coordinator.claimValidation(validatorId, fingerprint)) return;
  context.cursor.reset(modelRouter.route(validationRequirements(estimateTokens(finding))));
  const mission = session.beginMission(validatorId, "validator", context.cursor.route);
  session.dispatch({ type: "job-started", id: jobId });
  context.setActiveJobId(jobId);
  if (validatorId !== "validator") {
    session.dispatch({ type: "agent-spawned", id: validatorId, role: "validator" });
  }
  session.dispatch({ type: "agent", id: validatorId, status: "running" });
  try {
    let replyText = "";
    await context.cursor.run(
      async (_model, markToolInvoked) => {
        const validator = init(context.agentDefinition, {
          id: `mission-${context.missionIndex}-attempt-${mission.attemptedModels.length}`,
        });
        const receipt = await validator.dispatch({
          message: `Validate only finding ${fingerprint}, submit its outcome, then finish validation.`,
          initialData: { fingerprint, validatorId },
        });
        const reply = await validator.read(receipt, {
          onEvent: (chunk) => {
            if (chunk.type === "tool-input") markToolInvoked();
            session.captureAgentEvent(validatorId, chunk);
          },
        });
        session.captureUsage(reply.metadata, mission);
        replyText = reply.text;
      },
      (model) => session.recordModelAttempt(mission, model),
    );
    const completed = session.state.validations.some(
      (validation) => validation.fingerprint === fingerprint,
    );
    if (!completed) {
      coordinator.releaseValidation(fingerprint);
      session.dispatch({
        type: "job-failed",
        id: jobId,
        error: "Replay produced no submitted outcome",
        retryable: !finalAttempt,
      });
    }
    session.dispatch({
      type: "agent",
      id: validatorId,
      status: "finished",
      summary: completed ? replyText.slice(0, 100) : "Replay produced no submitted outcome.",
    });
  } catch (error) {
    coordinator.releaseValidation(fingerprint);
    const budgetExhausted = isRequestBudgetExhausted(error);
    session.dispatch({
      type: "job-failed",
      id: jobId,
      error: error instanceof Error ? error.message : String(error),
      retryable: isRuntimeStopError(error) || (!finalAttempt && budgetExhausted),
    });
    session.dispatch({
      type: "agent",
      id: validatorId,
      status: budgetExhausted ? "finished" : "failed",
      summary: budgetExhausted ? "Deferred until validation budget is reclaimed." : String(error),
    });
    if (isRuntimeStopError(error)) throw error;
  } finally {
    context.setActiveJobId(undefined);
  }
}
