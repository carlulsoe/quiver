import { ChainBudgetExceededError, replayExploitChain } from "./exploit-chain.ts";
import { isRuntimeStopError } from "./runner-errors.ts";
import { exploitChainJobId } from "./state.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import type { ValidationExecutorOptions } from "./validation-executor-types.ts";

export async function runExploitChainJobs(
  options: ValidationExecutorOptions,
  target: ScopedTarget,
  setActiveJobId: (jobId: string | undefined) => void,
): Promise<void> {
  const { session, profile, verification } = options;
  for (const chain of session.state.exploitChains) {
    const jobId = exploitChainJobId(chain.fingerprint);
    if (session.state.runtime.jobs.find(({ id }) => id === jobId)?.status !== "queued") continue;
    session.dispatch({ type: "job-started", id: jobId });
    setActiveJobId(jobId);
    try {
      session.dispatch({
        type: "exploit-chain-validation",
        validation: await replayExploitChain(
          target,
          chain,
          session.state.findings,
          profile,
          verification,
        ),
      });
    } catch (error) {
      const mutationStarted =
        session.state.runtime.jobs.find(({ id }) => id === jobId)?.mutationStarted === true;
      if (
        error instanceof ChainBudgetExceededError ||
        isRuntimeStopError(error) ||
        mutationStarted
      ) {
        session.dispatch({
          type: "job-failed",
          id: jobId,
          error: error instanceof Error ? error.message : String(error),
          retryable: isRuntimeStopError(error),
        });
        if (isRuntimeStopError(error)) throw error;
        continue;
      }
      session.dispatch({
        type: "exploit-chain-validation",
        validation: {
          fingerprint: chain.fingerprint,
          status: "rejected",
          summary: error instanceof Error ? error.message : String(error),
          checks: [
            {
              passed: false,
              description: "ordered exploit-chain replay completed without an error",
            },
          ],
        },
      });
    } finally {
      setActiveJobId(undefined);
    }
  }
}
