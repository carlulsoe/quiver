import type { Finding } from "../prototype/state.ts";

export interface VulnerableAppBenchmarkResult {
  coverage: number;
  totalExpected: number;
  truePositiveCount: number;
  falsePositiveCount: number;
  missedCount: number;
  precision: number;
  missedItems: unknown[];
  falsePositiveItems: unknown[];
}

type BenchmarkTransport = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

interface NativeBenchmarkResponse {
  coverage?: unknown;
  totalExpected?: unknown;
  detected?: unknown;
  missed?: unknown;
  unmatched?: unknown;
  missedItems?: unknown;
  unmatchedItems?: unknown;
}

export async function scoreVulnerableAppBenchmark(options: {
  target: URL;
  confirmedFindings: readonly Pick<Finding, "endpoint" | "method" | "cwe">[];
  transport?: BenchmarkTransport;
}): Promise<VulnerableAppBenchmarkResult> {
  if (!new Set(["127.0.0.1", "localhost", "[::1]"]).has(options.target.hostname)) {
    throw new Error("VulnerableApp benchmark scoring is restricted to loopback targets");
  }
  const endpoint = new URL("/VulnerableApp/scanner/benchmark", options.target.origin);
  const response = await (options.transport ?? fetch)(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      tool: "Quiver",
      scanType: "DAST",
      findings: options.confirmedFindings.map((finding) => ({
        url: finding.endpoint,
        method: finding.method ?? "GET",
        cwe: finding.cwe,
      })),
    }),
    redirect: "manual",
  });
  if (!response.ok) {
    throw new Error(`VulnerableApp benchmark endpoint returned ${response.status}`);
  }
  const body = (await response.json()) as NativeBenchmarkResponse;
  const totalExpected = countField(body.totalExpected, "totalExpected");
  const truePositiveCount = countField(body.detected, "detected");
  const falsePositiveCount = countField(body.unmatched, "unmatched");
  const missedCount = countField(body.missed, "missed");
  const nativeCoverage = percentageField(body.coverage, "coverage");
  if (truePositiveCount + missedCount !== totalExpected) {
    throw new Error(
      "VulnerableApp benchmark response counts are inconsistent: detected + missed must equal totalExpected",
    );
  }
  const expectedCoverage = totalExpected === 0 ? 0 : (truePositiveCount / totalExpected) * 100;
  if (Math.abs(nativeCoverage - expectedCoverage) > 0.51) {
    throw new Error(
      "VulnerableApp benchmark response coverage is inconsistent with detected and totalExpected",
    );
  }
  return {
    coverage: nativeCoverage / 100,
    totalExpected,
    truePositiveCount,
    falsePositiveCount,
    missedCount,
    precision:
      truePositiveCount + falsePositiveCount === 0
        ? 0
        : truePositiveCount / (truePositiveCount + falsePositiveCount),
    missedItems: arrayField(body.missedItems, "missedItems"),
    falsePositiveItems: arrayField(body.unmatchedItems, "unmatchedItems"),
  };
}

function countField(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`VulnerableApp benchmark response has invalid ${name}`);
  }
  return value;
}

function percentageField(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 100) {
    throw new Error(`VulnerableApp benchmark response has invalid ${name}`);
  }
  return value;
}

function arrayField(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`VulnerableApp benchmark response has invalid ${name}`);
  }
  return value;
}
