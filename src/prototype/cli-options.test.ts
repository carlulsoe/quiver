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
      ]),
    ).toEqual({
      target: new URL("http://127.0.0.1:8888"),
      reportPath: ".prototype/runs/latest.json",
      quiet: true,
      help: false,
    });
  });

  it("rejects a missing report path before parsing the next option", () => {
    expect(() => parseCliOptions(["--report", "--quiet"])).toThrow("--report requires a file path");
  });

  it("rejects ambiguous multiple targets", () => {
    expect(() => parseCliOptions(["http://127.0.0.1:8888", "http://localhost:8888"])).toThrow(
      "Only one target URL is allowed",
    );
  });
});
