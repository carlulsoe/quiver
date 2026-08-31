import { describe, expect, it } from "vitest";
import { parseCliOptions } from "./cli-options.ts";

describe("prototype CLI options", () => {
  it("accepts a report path without changing the target", () => {
    expect(
      parseCliOptions([
        "http://127.0.0.1:8888",
        "--report",
        ".prototype/runs/latest.json",
        "--quiet",
        "--budget",
        "45",
      ]),
    ).toEqual({
      target: new URL("http://127.0.0.1:8888"),
      profileId: "crapi",
      reportPath: ".prototype/runs/latest.json",
      quiet: true,
      help: false,
      requestBudget: 45,
    });
  });

  it("selects the randomized held-out profile and its default target", () => {
    expect(parseCliOptions(["--profile", "held-out"])).toMatchObject({
      profileId: "held-out",
      target: new URL("http://127.0.0.1:8899"),
    });
  });

  it("rejects unknown profiles", () => {
    expect(() => parseCliOptions(["--profile", "unknown"])).toThrow(
      "--profile must be one of: crapi, held-out",
    );
  });

  it("rejects a missing report path before parsing the next option", () => {
    expect(() => parseCliOptions(["--report", "--quiet"])).toThrow("--report requires a file path");
  });

  it("rejects a campaign budget too small to partition", () => {
    expect(() => parseCliOptions(["--budget", "2"])).toThrow(
      "--budget must be an integer of at least 3",
    );
  });

  it("rejects ambiguous multiple targets", () => {
    expect(() => parseCliOptions(["http://127.0.0.1:8888", "http://localhost:8888"])).toThrow(
      "Only one target URL is allowed",
    );
  });
});
