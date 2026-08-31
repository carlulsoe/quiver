export interface BenchmarkFinding {
  category: string;
  endpoint: string;
}

export interface CrapiBenchmarkInput {
  confirmedFindings: BenchmarkFinding[];
  requestsUsed: number;
}

export interface CrapiBenchmarkScore {
  expectedCount: number;
  truePositiveCount: number;
  falsePositiveCount: number;
  missedCount: number;
  unscoredCount: number;
  coverage: number;
  precision: number;
  requestsPerTruePositive: number | null;
  matchedBenchmarkIds: string[];
  missedBenchmarkIds: string[];
  falsePositiveFingerprints: string[];
  unscoredFingerprints: string[];
}

interface BenchmarkCase {
  id: string;
  endpoint: string;
  categories: readonly string[];
}

// Eval ground truth intentionally lives here rather than in the campaign or target profile.
export const CRAPI_READ_ONLY_BENCHMARK: readonly BenchmarkCase[] = [
  {
    id: "vehicle-location-bola",
    endpoint: "/identity/api/v2/vehicle/{id}/location",
    categories: ["broken-object-authorization"],
  },
  {
    id: "community-author-data-exposure",
    endpoint: "/community/api/v2/community/posts/recent",
    categories: ["excessive-data-exposure", "sensitive-data-exposure"],
  },
  {
    id: "profile-video-internal-property",
    endpoint: "/identity/api/v2/user/videos/{id}",
    categories: ["excessive-data-exposure", "sensitive-data-exposure"],
  },
  {
    id: "unauthenticated-order-access",
    endpoint: "/workshop/api/shop/orders/{id}",
    categories: [
      "broken-object-authorization",
      "broken-function-authorization",
      "security-misconfiguration",
      "other",
    ],
  },
] as const;

const CRAPI_SAFE_CONTROLS: readonly BenchmarkCase[] = [
  {
    id: "owned-vehicle-list-is-token-scoped",
    endpoint: "/identity/api/v2/vehicle/vehicles",
    categories: ["broken-object-authorization"],
  },
  {
    id: "profile-video-enforces-object-ownership",
    endpoint: "/identity/api/v2/user/videos/{id}",
    categories: ["broken-object-authorization"],
  },
  {
    id: "product-list-requires-authentication",
    endpoint: "/workshop/api/shop/products",
    categories: ["broken-function-authorization", "security-misconfiguration", "other"],
  },
  {
    id: "mechanic-list-requires-authentication",
    endpoint: "/workshop/api/mechanic",
    categories: ["broken-function-authorization", "security-misconfiguration", "other"],
  },
] as const;

export function scoreCrapiReadOnlyBenchmark(input: CrapiBenchmarkInput): CrapiBenchmarkScore {
  if (!Number.isFinite(input.requestsUsed) || input.requestsUsed < 0) {
    throw new Error("requestsUsed must be a non-negative finite number");
  }

  const findings = uniqueFindings(input.confirmedFindings);
  const matchedIds = new Set<string>();
  const falsePositiveFingerprints: string[] = [];
  const unscoredFingerprints: string[] = [];

  for (const finding of findings) {
    const findingFingerprint = fingerprint(finding);
    const expected = CRAPI_READ_ONLY_BENCHMARK.find((testCase) => matches(testCase, finding));
    if (expected) {
      matchedIds.add(expected.id);
      continue;
    }
    if (CRAPI_SAFE_CONTROLS.some((control) => matches(control, finding))) {
      falsePositiveFingerprints.push(findingFingerprint);
      continue;
    }
    unscoredFingerprints.push(findingFingerprint);
  }

  const matchedBenchmarkIds = CRAPI_READ_ONLY_BENCHMARK.map(({ id }) => id).filter((id) =>
    matchedIds.has(id),
  );
  const missedBenchmarkIds = CRAPI_READ_ONLY_BENCHMARK.map(({ id }) => id).filter(
    (id) => !matchedIds.has(id),
  );
  const truePositiveCount = matchedBenchmarkIds.length;
  const falsePositiveCount = falsePositiveFingerprints.length;
  const scoredClaimCount = truePositiveCount + falsePositiveCount;

  return {
    expectedCount: CRAPI_READ_ONLY_BENCHMARK.length,
    truePositiveCount,
    falsePositiveCount,
    missedCount: missedBenchmarkIds.length,
    unscoredCount: unscoredFingerprints.length,
    coverage: truePositiveCount / CRAPI_READ_ONLY_BENCHMARK.length,
    precision: scoredClaimCount === 0 ? 0 : truePositiveCount / scoredClaimCount,
    requestsPerTruePositive:
      truePositiveCount === 0 ? null : input.requestsUsed / truePositiveCount,
    matchedBenchmarkIds,
    missedBenchmarkIds,
    falsePositiveFingerprints,
    unscoredFingerprints,
  };
}

function matches(testCase: BenchmarkCase, finding: BenchmarkFinding): boolean {
  return (
    testCase.endpoint === normalizeEndpoint(finding.endpoint) &&
    testCase.categories.includes(finding.category)
  );
}

function uniqueFindings(findings: readonly BenchmarkFinding[]): BenchmarkFinding[] {
  return Array.from(
    new Map(findings.map((finding) => [fingerprint(finding), finding] as const)).values(),
  );
}

function fingerprint(finding: BenchmarkFinding): string {
  return `${finding.category}:GET:${normalizeEndpoint(finding.endpoint)}`;
}

function normalizeEndpoint(endpoint: string): string {
  const url = new URL(endpoint, "http://benchmark.invalid");
  const path = url.pathname
    .split("/")
    .map((encodedSegment) => {
      const segment = decodeURIComponent(encodedSegment);
      return /^\d+$/.test(segment) ||
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          segment,
        ) ||
        /^(?:<[^>]+>|\{[^}]+\})$/.test(segment)
        ? "{id}"
        : segment;
    })
    .join("/");
  return path.length > 1 ? path.replace(/\/$/, "") : path;
}
