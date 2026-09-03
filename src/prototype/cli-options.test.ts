import { describe, expect, it } from "vitest";
import { CLI_HELP, parseCliOptions } from "./cli-options.ts";

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

  it.each([
    ["broken-crystals", "http://127.0.0.1:3000/"],
    ["vulnerableapp", "http://127.0.0.1:9090/VulnerableApp/"],
    ["vampi-vulnerable", "http://127.0.0.1:5002/ui/"],
    ["vampi-secure", "http://127.0.0.1:5001/ui/"],
  ])("selects the %s profile and default target", (profile, target) => {
    expect(parseCliOptions(["--profile", profile])).toMatchObject({
      profileId: profile,
      target: new URL(target),
    });
  });

  it("accepts supplied OpenAPI and context files", () => {
    expect(parseCliOptions(["--openapi", "api.yaml", "--context", "target.md"])).toMatchObject({
      openApiPath: "api.yaml",
      contextPath: "target.md",
    });
  });

  it("accepts a durable campaign id and JSONL store", () => {
    expect(
      parseCliOptions([
        "--campaign-id",
        "nightly-crapi",
        "--campaign-store",
        ".prototype/campaigns.jsonl",
      ]),
    ).toMatchObject({
      campaignId: "nightly-crapi",
      campaignStorePath: ".prototype/campaigns.jsonl",
    });
  });

  it("rejects missing supplied-input paths", () => {
    expect(() => parseCliOptions(["--openapi", "--quiet"])).toThrow(
      "--openapi requires a file path",
    );
    expect(() => parseCliOptions(["--context"])).toThrow("--context requires a file path");
  });

  it("rejects unknown profiles", () => {
    expect(() => parseCliOptions(["--profile", "unknown"])).toThrow(
      "--profile must be one of: broken-crystals, crapi, held-out, vampi-secure, vampi-vulnerable, vulnerableapp",
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

  it("documents the process exit-code contract", () => {
    expect(CLI_HELP).toContain("0  Campaign completed with at least one confirmed finding");
    expect(CLI_HELP).toContain("1  Campaign failed");
    expect(CLI_HELP).toContain("2  Campaign completed without a confirmed finding");
  });
});
