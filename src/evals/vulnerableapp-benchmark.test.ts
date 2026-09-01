import { describe, expect, it, vi } from "vitest";
import { scoreVulnerableAppBenchmark } from "./vulnerableapp-benchmark.ts";

describe("VulnerableApp native benchmark adapter", () => {
  it("submits confirmed findings and reports native unmatched items as false positives", async () => {
    const transport = vi.fn(async (_input: string | URL | Request, _init?: RequestInit) =>
      Response.json({
        coverage: 25,
        totalExpected: 8,
        detected: 2,
        missed: 6,
        unmatched: 1,
        missedItems: [{ url: "/missed" }],
        unmatchedItems: [{ url: "/safe" }],
      }),
    );
    const score = await scoreVulnerableAppBenchmark({
      target: new URL("http://127.0.0.1:9090/VulnerableApp/"),
      confirmedFindings: [{ endpoint: "/example", method: "GET", cwe: "CWE-200" }],
      transport,
    });

    expect(score).toMatchObject({
      coverage: 0.25,
      truePositiveCount: 2,
      falsePositiveCount: 1,
      precision: 2 / 3,
    });
    expect(transport).toHaveBeenCalledWith(
      new URL("http://127.0.0.1:9090/VulnerableApp/scanner/benchmark"),
      expect.objectContaining({ method: "POST" }),
    );
    const request = transport.mock.calls[0]![1] as RequestInit;
    expect(JSON.parse(String(request.body))).toEqual({
      tool: "Quiver",
      scanType: "DAST",
      findings: [{ url: "/example", method: "GET", cwe: "CWE-200" }],
    });
  });

  it("rejects non-loopback scoring targets", async () => {
    await expect(
      scoreVulnerableAppBenchmark({
        target: new URL("https://example.com"),
        confirmedFindings: [],
      }),
    ).rejects.toThrow("restricted to loopback targets");
  });

  it("rejects internally inconsistent native benchmark results", async () => {
    await expect(
      scoreVulnerableAppBenchmark({
        target: new URL("http://127.0.0.1:9090/VulnerableApp/"),
        confirmedFindings: [],
        transport: async () =>
          Response.json({
            coverage: 75,
            totalExpected: 8,
            detected: 2,
            missed: 5,
            unmatched: 0,
            missedItems: [],
            unmatchedItems: [],
          }),
      }),
    ).rejects.toThrow("detected + missed must equal totalExpected");
  });
});
