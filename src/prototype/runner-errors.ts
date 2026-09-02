import {
  CampaignCancelledError,
  CampaignHaltedError,
  CampaignPausedError,
  OutsideTestingWindowError,
} from "./runtime-safety.ts";
import { RequestBudgetExceededError } from "./scoped-target.ts";
import { ReplayBudgetExceededError } from "./verification.ts";

export function isRequestBudgetExhausted<T>(error: T): boolean {
  return (
    error instanceof RequestBudgetExceededError ||
    error instanceof ReplayBudgetExceededError ||
    String(error).includes("Request budget exhausted")
  );
}

export function isRuntimeStopError<T>(error: T): boolean {
  return (
    error instanceof CampaignPausedError ||
    error instanceof CampaignCancelledError ||
    error instanceof CampaignHaltedError ||
    error instanceof OutsideTestingWindowError
  );
}
