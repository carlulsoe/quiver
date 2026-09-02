import { describe, expect, it } from "vitest";
import {
  CampaignHaltedError,
  CampaignPausedError,
  OutsideTestingWindowError,
  RuntimeSafetyController,
  classifyHttpStatus,
} from "./runtime-safety.ts";

describe("runtime safety controller", () => {
  it("enforces a rolling RPS limit", async () => {
    let now = 1_000;
    const sleeps: number[] = [];
    const controller = new RuntimeSafetyController(
      { requestsPerSecond: 2, maxConcurrency: 1 },
      {
        now: () => now,
        sleep: async (milliseconds) => {
          sleeps.push(milliseconds);
          now += milliseconds;
        },
      },
    );

    await controller.execute(async () => "first");
    await controller.execute(async () => "second");
    await controller.execute(async () => "third");

    expect(sleeps).toEqual([1_000]);
  });

  it("caps concurrent request execution", async () => {
    let active = 0;
    let maximum = 0;
    const controller = new RuntimeSafetyController({
      requestsPerSecond: 100,
      maxConcurrency: 2,
    });
    const operation = () =>
      controller.execute(async () => {
        active += 1;
        maximum = Math.max(maximum, active);
        await new Promise((resolve) => setTimeout(resolve, 5));
        active -= 1;
      });

    await Promise.all([operation(), operation(), operation(), operation()]);

    expect(maximum).toBe(2);
  });

  it("rate-limits queued requests at their actual start time", async () => {
    let now = 0;
    let releaseFirst!: () => void;
    const starts: number[] = [];
    const controller = new RuntimeSafetyController(
      { requestsPerSecond: 2, maxConcurrency: 1 },
      {
        now: () => now,
        sleep: async (milliseconds) => {
          now += milliseconds;
        },
      },
    );
    const first = controller.execute(async () => {
      starts.push(now);
      await new Promise<void>((resolve) => {
        releaseFirst = resolve;
      });
    });
    while (releaseFirst === undefined) await Promise.resolve();
    const queued = [1, 2, 3].map(() =>
      controller.execute(async () => {
        starts.push(now);
      }),
    );
    await Promise.resolve();
    now = 1_500;
    releaseFirst();

    await Promise.all([first, ...queued]);

    expect(starts).toEqual([0, 1_500, 1_500, 2_500]);
  });

  it("reserves a released slot for the oldest concurrency waiter", async () => {
    const controller = new RuntimeSafetyController({
      requestsPerSecond: 100,
      maxConcurrency: 1,
    });
    const first = await controller.acquire();
    const waiting = controller.acquire();
    first.release();
    let stealingResolved = false;
    const stealing = controller.acquire().then((lease) => {
      stealingResolved = true;
      return lease;
    });

    const second = await waiting;
    await Promise.resolve();
    expect(controller.activeRequests).toBe(1);
    expect(stealingResolved).toBe(false);
    second.release();
    const third = await stealing;
    expect(controller.activeRequests).toBe(1);
    third.release();
    expect(controller.activeRequests).toBe(0);
  });

  it("fails closed outside an approved testing window and while paused", async () => {
    let status: "running" | "paused" = "running";
    const controller = new RuntimeSafetyController(
      {
        testingWindows: [{ start: "2026-09-02T10:00:00.000Z", end: "2026-09-02T11:00:00.000Z" }],
      },
      {
        now: () => Date.parse("2026-09-02T09:59:59.000Z"),
        controlStatus: () => status,
      },
    );

    await expect(controller.execute(async () => undefined)).rejects.toBeInstanceOf(
      OutsideTestingWindowError,
    );
    status = "paused";
    await expect(controller.execute(async () => undefined)).rejects.toBeInstanceOf(
      CampaignPausedError,
    );
  });

  it("automatically halts after repeated disruptive target responses", async () => {
    const haltReasons: string[] = [];
    const controller = new RuntimeSafetyController(
      {
        requestsPerSecond: 100,
        maxDisruptiveResponses: 2,
        maxConsecutiveFailures: 5,
      },
      { onHalt: (reason) => haltReasons.push(reason) },
    );

    await controller.execute(
      async () => ({ status: 429 }),
      ({ status }) => classifyHttpStatus(status),
    );
    await controller.execute(
      async () => ({ status: 503 }),
      ({ status }) => classifyHttpStatus(status),
    );

    expect(haltReasons).toEqual(["Automatic halt after 2 disruptive target responses"]);
    await expect(controller.execute(async () => ({ status: 200 }))).rejects.toBeInstanceOf(
      CampaignHaltedError,
    );
  });

  it("halts before admission when a restored failure counter reached its threshold", async () => {
    const haltReasons: string[] = [];
    const controller = new RuntimeSafetyController(
      { maxConsecutiveFailures: 3 },
      {
        initialConsecutiveFailures: 3,
        onHalt: (reason) => haltReasons.push(reason),
      },
    );

    expect(haltReasons).toEqual(["Automatic halt after 3 consecutive request failures"]);
    await expect(controller.execute(async () => "not sent")).rejects.toBeInstanceOf(
      CampaignHaltedError,
    );
  });

  it("releases admission without counting local control-flow errors", async () => {
    let failures = 0;
    const controller = new RuntimeSafetyController(
      { requestsPerSecond: 100, maxConsecutiveFailures: 1 },
      { onFailure: () => (failures += 1) },
    );

    await expect(
      controller.execute(
        async () => {
          throw new Error("local budget exhausted");
        },
        undefined,
        () => "ignore",
      ),
    ).rejects.toThrow("local budget exhausted");
    await expect(controller.execute(async () => "sent")).resolves.toBe("sent");
    expect(failures).toBe(0);
  });
});
