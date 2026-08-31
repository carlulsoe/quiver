import type { HttpObservation } from "./scoped-target.ts";
import type { RestMethod } from "./scoped-target.ts";
import {
  fingerprintFinding,
  type Finding,
  type FindingInput,
  type ReproductionRequest,
  type TestedRequest,
  type ValidationObservation,
} from "./state.ts";

export interface LedgerRequest {
  agentId: string;
  path: string;
  method?: RestMethod;
  headers?: Record<string, string>;
  body?: string;
  authenticated: boolean;
}

export interface LedgerRequestResult {
  observation: HttpObservation;
  reused: boolean;
}

export interface LedgerFinding {
  agentId: string;
  fingerprint: string;
  title: string;
  endpoint: string;
}

export interface CampaignLedgerSnapshot {
  testedRequests: TestedRequest[];
  findings: LedgerFinding[];
}

export interface CampaignLedgerOptions {
  onTestedRequest?: (request: TestedRequest) => void;
  onFinding?: (finding: FindingInput) => void;
}

interface RequestEntry {
  promise: Promise<HttpObservation>;
  observation?: HttpObservation;
  tested?: TestedRequest;
}

/** Coordinates explorers at the point where duplicate work becomes expensive. */
export class CampaignLedger {
  readonly #requests = new Map<string, RequestEntry>();
  readonly #findings = new Map<string, Finding>();
  readonly #onTestedRequest?: (request: TestedRequest) => void;
  readonly #onFinding?: (finding: FindingInput) => void;

  constructor(options: CampaignLedgerOptions = {}) {
    this.#onTestedRequest = options.onTestedRequest;
    this.#onFinding = options.onFinding;
  }

  async request(
    request: LedgerRequest,
    execute: () => Promise<HttpObservation>,
  ): Promise<LedgerRequestResult> {
    const key = requestKey(request);
    const existing = this.#requests.get(key);
    if (existing) return { observation: await existing.promise, reused: true };

    let entry: RequestEntry;
    const promise = Promise.resolve()
      .then(execute)
      .then((observation) => {
        const tested: TestedRequest = {
          agentId: request.agentId,
          method: observation.method ?? request.method ?? "GET",
          path: observation.path,
          authenticated: request.authenticated,
          status: observation.status,
        };
        entry.tested = tested;
        entry.observation = observation;
        this.#onTestedRequest?.(tested);
        return observation;
      })
      .catch((error: unknown) => {
        if (this.#requests.get(key) === entry) this.#requests.delete(key);
        throw error;
      });
    entry = { promise };
    this.#requests.set(key, entry);
    return { observation: await entry.promise, reused: false };
  }

  recordFinding(input: FindingInput): { accepted: boolean; fingerprint: string } {
    const fingerprint = fingerprintFinding(input);
    if (this.#findings.has(fingerprint)) return { accepted: false, fingerprint };

    this.#findings.set(fingerprint, { ...input, fingerprint });
    this.#onFinding?.(input);
    return { accepted: true, fingerprint };
  }

  observationsFor(
    reproduction: readonly ReproductionRequest[],
  ): ValidationObservation[] | undefined {
    const observations: ValidationObservation[] = [];
    for (const request of reproduction) {
      const observation = this.#requests.get(requestKey(request))?.observation;
      if (!observation) return undefined;
      observations.push({
        method: observation.method ?? request.method ?? "GET",
        status: observation.status,
        path: observation.path,
        authenticated: request.authenticated,
        body: observation.body,
        truncated: observation.truncated ?? false,
      });
    }
    return observations;
  }

  snapshot(): CampaignLedgerSnapshot {
    return {
      testedRequests: [...this.#requests.values()]
        .flatMap((entry) => (entry.tested ? [entry.tested] : []))
        .map((request) => ({ ...request })),
      findings: [...this.#findings.values()].map(({ agentId, fingerprint, title, endpoint }) => ({
        agentId,
        fingerprint,
        title,
        endpoint,
      })),
    };
  }
}

function requestKey(
  request: Pick<LedgerRequest, "path" | "method" | "headers" | "body" | "authenticated">,
): string {
  const url = new URL(request.path, "http://scope.invalid");
  url.searchParams.sort();
  const headers = Object.entries(request.headers ?? {})
    .map(([name, value]) => [name.toLowerCase(), value] as const)
    .sort(([left], [right]) => left.localeCompare(right));
  return JSON.stringify([
    request.method ?? "GET",
    request.authenticated ? "authenticated" : "anonymous",
    `${url.pathname}${url.search}`,
    headers,
    request.body ?? "",
  ]);
}
