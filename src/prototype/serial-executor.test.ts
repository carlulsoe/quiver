import { describe, expect, it } from "vitest";
import { createSerialExecutor } from "./serial-executor.ts";

describe("serial executor", () => {
  it("does not overlap operations submitted concurrently", async () => {
    const serialize = createSerialExecutor();
    const events: string[] = [];
    let releaseFirst!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const first = serialize(async () => {
      events.push("first:start");
      await gate;
      events.push("first:end");
    });
    const second = serialize(async () => {
      events.push("second:start");
      events.push("second:end");
    });

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(events).toEqual(["first:start"]);
    releaseFirst();
    await Promise.all([first, second]);
    expect(events).toEqual(["first:start", "first:end", "second:start", "second:end"]);
  });
});
