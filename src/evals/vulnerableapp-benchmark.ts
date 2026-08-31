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
  const totalExpected = numberField(body.totalExpected, "totalExpected");
  const truePositiveCount = numberField(body.detected, "detected");
  const falsePositiveCount = numberField(body.unmatched, "unmatched");
  const missedCount = numberField(body.missed, "missed");
  const nativeCoverage = numberField(body.coverage, "coverage");
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

function numberField(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
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
