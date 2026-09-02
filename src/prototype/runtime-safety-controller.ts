import { assertRuntimeSafetyPolicy, withinTestingWindow } from "./runtime-safety-policy.ts";
import {
  CampaignCancelledError,
  CampaignHaltedError,
  CampaignPausedError,
  DEFAULT_RUNTIME_SAFETY_POLICY,
  OutsideTestingWindowError,
  type RuntimeRequestLease,
  type RuntimeSafetyEvents,
  type RuntimeSafetyPolicy,
} from "./runtime-safety-types.ts";

/**
 * Shared request scheduler for one campaign. It owns admission, rate/concurrency limits, testing
 * windows, and the automatic circuit breaker while callers only supply the network operation.
 */
export class RuntimeSafetyController {
  readonly #policy: RuntimeSafetyPolicy;
  readonly #events: RuntimeSafetyEvents;
  readonly #starts: number[] = [];
  readonly #slotWaiters: Array<() => void> = [];
  #active = 0;
  #admissionTail = Promise.resolve();
  #consecutiveFailures: number;
  #disruptiveResponses: number;
  #haltReason?: string;

  constructor(policy: Partial<RuntimeSafetyPolicy> = {}, events: RuntimeSafetyEvents = {}) {
    this.#policy = { ...DEFAULT_RUNTIME_SAFETY_POLICY, ...policy };
    assertRuntimeSafetyPolicy(this.#policy);
    this.#events = events;
    this.#consecutiveFailures = events.initialConsecutiveFailures ?? 0;
    this.#disruptiveResponses = events.initialDisruptiveResponses ?? 0;
    if (this.#consecutiveFailures >= this.#policy.maxConsecutiveFailures) {
      this.#halt(`Automatic halt after ${this.#consecutiveFailures} consecutive request failures`);
    } else if (this.#disruptiveResponses >= this.#policy.maxDisruptiveResponses) {
      this.#halt(`Automatic halt after ${this.#disruptiveResponses} disruptive target responses`);
    }
  }

  get activeRequests(): number {
    return this.#active;
  }

  get haltReason(): string | undefined {
    return this.#haltReason;
  }

  assertReady(): void {
    if (this.#haltReason) throw new CampaignHaltedError(this.#haltReason);
    const status = this.#events.controlStatus?.() ?? "running";
    if (status === "paused") throw new CampaignPausedError("Campaign is paused");
    if (status === "cancelled") throw new CampaignCancelledError("Campaign is cancelled");
    if (status === "halted") throw new CampaignHaltedError("Campaign is halted");
    const windows = this.#policy.testingWindows;
    if (windows?.length && !windows.some((window) => withinTestingWindow(this.#now(), window))) {
      throw new OutsideTestingWindowError(
        "Current time is outside every configured testing window",
      );
    }
  }

  async execute<T>(
    operation: () => Promise<T>,
    classify: (result: T) => "success" | "failure" | "disruptive" = () => "success",
    classifyError: (cause: unknown) => "failure" | "disruptive" | "ignore" = () => "failure",
  ): Promise<T> {
    const lease = await this.acquire();
    try {
      const result = await operation();
      const outcome = classify(result);
      lease.finish(outcome);
      return result;
    } catch (error) {
      const outcome = classifyError(error);
      if (outcome === "ignore") lease.release();
      else lease.fail(outcome === "disruptive");
      throw error;
    }
  }

  /** Acquires campaign-wide admission for transports that report completion asynchronously. */
  async acquire(): Promise<RuntimeRequestLease> {
    this.assertReady();
    await this.#acquireSlot();
    try {
      await this.#admitRate();
      this.assertReady();
    } catch (error) {
      this.#releaseSlot();
      throw error;
    }
    let released = false;
    const releaseSlot = () => {
      if (released) return false;
      released = true;
      this.#releaseSlot();
      return true;
    };
    const release = (outcome: "success" | "failure" | "disruptive") => {
      if (!releaseSlot()) return;
      if (outcome === "success") this.#recordSuccess();
      else this.#recordFailure(outcome === "disruptive");
    };
    return {
      finish: (outcome = "success") => release(outcome),
      fail: (disruptive = false) => release(disruptive ? "disruptive" : "failure"),
      release: () => {
        releaseSlot();
      },
    };
  }

  #admitRate(): Promise<void> {
    const previous = this.#admissionTail;
    let release!: () => void;
    this.#admissionTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    return previous.then(async () => {
      try {
        this.assertReady();
        const interval = 1_000;
        let now = this.#now();
        while (this.#starts[0] !== undefined && now - this.#starts[0] >= interval) {
          this.#starts.shift();
        }
        if (this.#starts.length >= this.#policy.requestsPerSecond) {
          await this.#sleep(interval - (now - this.#starts[0]!));
          this.assertReady();
          now = this.#now();
          while (this.#starts[0] !== undefined && now - this.#starts[0] >= interval) {
            this.#starts.shift();
          }
        }
        this.#starts.push(now);
      } finally {
        release();
      }
    });
  }

  async #acquireSlot(): Promise<void> {
    if (this.#active >= this.#policy.maxConcurrency) {
      await new Promise<void>((resolve) => this.#slotWaiters.push(resolve));
      return;
    }
    this.#active += 1;
  }

  #releaseSlot(): void {
    const waiter = this.#slotWaiters.shift();
    if (waiter) {
      waiter();
      return;
    }
    this.#active -= 1;
  }

  #recordSuccess(): void {
    const recovered = this.#consecutiveFailures > 0;
    this.#consecutiveFailures = 0;
    if (recovered) this.#events.onSuccess?.();
  }

  #recordFailure(disruptive: boolean): void {
    this.#consecutiveFailures += 1;
    if (disruptive) this.#disruptiveResponses += 1;
    this.#events.onFailure?.(disruptive);
    if (this.#consecutiveFailures >= this.#policy.maxConsecutiveFailures) {
      this.#halt(`Automatic halt after ${this.#consecutiveFailures} consecutive request failures`);
    } else if (this.#disruptiveResponses >= this.#policy.maxDisruptiveResponses) {
      this.#halt(`Automatic halt after ${this.#disruptiveResponses} disruptive target responses`);
    }
  }

  #halt(reason: string): void {
    if (this.#haltReason) return;
    this.#haltReason = reason;
    this.#events.onHalt?.(reason);
  }

  #now(): number {
    return this.#events.now?.() ?? Date.now();
  }

  #sleep(milliseconds: number): Promise<void> {
    return (
      this.#events.sleep?.(milliseconds) ??
      new Promise<void>((resolve) => setTimeout(resolve, milliseconds))
    );
  }
}
