import { normalizeEndpoint } from "./endpoint.ts";
import { fingerprintFinding, type FindingInput, type TestedRequest } from "./state.ts";
import { actorIds, type ActorId } from "./sessions.ts";

export type SpecialistKind =
  | "authorization"
  | "authentication"
  | "data-exposure"
  | "request-semantics";

export type HypothesisStatus = "queued" | "testing" | "supported" | "rejected";

export interface CoordinatedTask {
  route: string;
  method: string;
  actorId: ActorId;
  source: "uncovered-surface" | "incoming-evidence" | "worker-hypothesis";
  reason: string;
  hypothesisId?: string;
}

export interface CoordinatorHypothesis {
  id: string;
  title: string;
  method: string;
  route: string;
  specialty: SpecialistKind;
  status: HypothesisStatus;
  confidence: number;
  rationale: string;
  nextStep: string;
  proposedBy: string;
  assignedAgentId?: string;
  evidenceSignals: string[];
}

export interface HypothesisInput {
  title: string;
  method?: string;
  route: string;
  specialty: SpecialistKind;
  confidence: number;
  rationale: string;
  nextStep: string;
}

export interface WorkerDebriefInput {
  summary: string;
  exhausted: boolean;
  hypotheses?: readonly HypothesisInput[];
}

export interface WorkerDebrief extends WorkerDebriefInput {
  agentId: string;
  hypotheses: HypothesisInput[];
}

export interface WorkerBudget {
  allocated: number;
  used: number;
  remaining: number;
}

export interface WorkAssignment {
  agentId: string;
  tasks: CoordinatedTask[];
  uncoveredRouteCount: number;
  evidenceSignals: string[];
  hypotheses: CoordinatorHypothesis[];
  specialty?: SpecialistKind;
  budget: WorkerBudget;
}

export interface SpecialistPlan {
  agentId: string;
  specialty: SpecialistKind;
  focus: string;
  hypothesisIds: string[];
  requestBudget: number;
}

export interface CoordinatorCoverage {
  discoveredOperations: number;
  testedOperations: number;
  operationCoverage: number;
  testedAccessModes: number;
  totalAccessModes: number;
  accessModeCoverage: number;
}

export interface CoordinatorBudget {
  total: number | null;
  consumed: number;
  allocated: number;
  available: number | null;
  workers: Record<string, WorkerBudget>;
}

export interface ValidationQueueItem {
  fingerprint: string;
  status: "queued" | "validating" | "complete";
  validatorId?: string;
  outcome?: "confirmed" | "rejected";
}

export interface CoordinatorSnapshot {
  revision: number;
  coverage: CoordinatorCoverage;
  hypotheses: CoordinatorHypothesis[];
  debriefs: WorkerDebrief[];
  specialists: SpecialistPlan[];
  validationQueue: ValidationQueueItem[];
  budget: CoordinatorBudget;
}

export interface AdaptiveCoordinatorOptions {
  actorIds?: readonly ActorId[];
  requestBudget?: number;
  expectedWorkers?: number;
  onChange?: (snapshot: CoordinatorSnapshot) => void;
}

interface Candidate extends CoordinatedTask {
  key: string;
  priority: number;
}

interface MutableWorkerBudget {
  allocated: number;
  used: number;
}

/**
 * Persistent campaign decision engine. Workers are deliberately short-lived; this object owns
 * the campaign memory, coverage model, hypotheses, request allocations, and validation queue.
 */
export class PersistentCoordinator {
  readonly #operations = new Map<string, { method: string; route: string }>();
  readonly #tested = new Map<string, TestedRequest[]>();
  readonly #claims = new Map<string, string>();
  readonly #findings = new Set<string>();
  readonly #hypotheses = new Map<string, CoordinatorHypothesis>();
  readonly #debriefs = new Map<string, WorkerDebrief>();
  readonly #allocations = new Map<string, MutableWorkerBudget>();
  readonly #specialists = new Map<string, SpecialistPlan>();
  readonly #validationQueue = new Map<string, ValidationQueueItem>();
  readonly #actorIds: readonly ActorId[];
  readonly #requestBudget?: number;
  readonly #expectedWorkers: number;
  readonly #onChange?: (snapshot: CoordinatorSnapshot) => void;
  #requestsConsumed = 0;
  #hypothesisSequence = 0;
  #specialistSequence = 0;
  #revision = 0;

  constructor(options: AdaptiveCoordinatorOptions = {}) {
    this.#actorIds = uniqueActorIds(options.actorIds ?? [actorIds.anonymous, actorIds.ordinary]);
    if (
      options.requestBudget !== undefined &&
      (!Number.isInteger(options.requestBudget) || options.requestBudget < 0)
    ) {
      throw new Error("Coordinator request budget must be a non-negative integer");
    }
    this.#requestBudget = options.requestBudget;
    this.#expectedWorkers = Math.max(1, options.expectedWorkers ?? 1);
    this.#onChange = options.onChange;
  }

  discoverRoutes(routes: readonly string[]): void {
    this.discoverOperations(routes.map((path) => ({ method: "GET", path })));
  }

  discoverOperations(operations: readonly { method: string; path: string }[]): void {
    let changed = false;
    for (const { method, path: route } of operations) {
      const normalized = safeCoordinatorKey(route);
      if (!normalized) continue;
      const normalizedMethod = method.toUpperCase();
      const key = operationKey(normalizedMethod, normalized);
      if (this.#operations.has(key)) continue;
      this.#operations.set(key, { method: normalizedMethod, route });
      changed = true;
    }
    if (changed) this.#changed();
  }

  /** Records a real target request, including browser mapping requests. */
  observeBudgetUse(count = 1): void {
    if (!Number.isInteger(count) || count < 1) throw new Error("Budget use must be positive");
    this.#requestsConsumed += count;
    this.#changed();
  }

  canRequest(agentId: string): boolean {
    if (this.#requestBudget !== undefined && this.#requestsConsumed >= this.#requestBudget) {
      return false;
    }
    const allocation = this.#allocations.get(agentId);
    return allocation === undefined || allocation.used < allocation.allocated;
  }

  observeRequest(request: TestedRequest): void {
    const operation = this.#operationForRequest(request.method ?? "GET", request.path);
    if (!operation) return;
    const requests = this.#tested.get(operation) ?? [];
    requests.push({ ...request });
    this.#tested.set(operation, requests);
    this.#claims.delete(taskKey(operation, request.actorId));
    const allocation = this.#allocations.get(request.agentId);
    if (allocation && allocation.used < allocation.allocated) allocation.used += 1;
    this.#updateEvidenceHypothesis(operation, requests);
    this.#changed();
  }

  observeFinding(finding: FindingInput): string {
    const route = safeNormalizeEndpoint(finding.endpoint);
    if (route) this.#findings.add(operationKey(finding.method ?? "GET", route));
    const fingerprint = fingerprintFinding(finding);
    if (!this.#validationQueue.has(fingerprint)) {
      this.#validationQueue.set(fingerprint, { fingerprint, status: "queued" });
    }
    for (const hypothesis of this.#hypotheses.values()) {
      if (
        hypothesis.status !== "rejected" &&
        route &&
        hypothesis.method === (finding.method ?? "GET") &&
        routeMatches(hypothesis.route, route)
      ) {
        hypothesis.status = "supported";
        hypothesis.evidenceSignals.push(`Finding ${fingerprint} supplies deterministic proof.`);
      }
    }
    this.#changed();
    return fingerprint;
  }

  recordValidation(
    fingerprint: string,
    outcome: "confirmed" | "rejected",
    validatorId = "validator",
  ): void {
    const item = this.#validationQueue.get(fingerprint);
    if (!item) return;
    this.#validationQueue.set(fingerprint, {
      fingerprint,
      status: "complete",
      validatorId,
      outcome,
    });
    this.#changed();
  }

  claimValidation(validatorId = "validator", fingerprint?: string): string | undefined {
    const item = fingerprint
      ? this.#validationQueue.get(fingerprint)
      : [...this.#validationQueue.values()].find(({ status }) => status === "queued");
    if (item?.status !== "queued") return undefined;
    this.#validationQueue.set(item.fingerprint, {
      ...item,
      status: "validating",
      validatorId,
    });
    this.#changed();
    return item.fingerprint;
  }

  releaseValidation(fingerprint: string): void {
    const item = this.#validationQueue.get(fingerprint);
    if (!item || item.status === "complete") return;
    this.#validationQueue.set(fingerprint, { fingerprint, status: "queued" });
    this.#changed();
  }

  debrief(agentId: string, input: WorkerDebriefInput): WorkerDebrief {
    const debrief: WorkerDebrief = {
      agentId,
      summary: input.summary,
      exhausted: input.exhausted,
      hypotheses: (input.hypotheses ?? []).map((hypothesis) => ({ ...hypothesis })),
    };
    this.#debriefs.set(agentId, debrief);
    for (const hypothesis of debrief.hypotheses) this.#recordHypothesis(agentId, hypothesis);
    if (input.exhausted) {
      for (const hypothesis of this.#hypotheses.values()) {
        if (hypothesis.assignedAgentId === agentId && hypothesis.status === "testing") {
          hypothesis.status = "rejected";
          delete hypothesis.assignedAgentId;
          hypothesis.evidenceSignals.push(`${agentId} exhausted this lead during its mission.`);
        }
      }
    }
    this.#changed();
    return { ...debrief, hypotheses: debrief.hypotheses.map((item) => ({ ...item })) };
  }

  release(agentId: string): void {
    let changed = false;
    for (const [key, owner] of this.#claims) {
      if (owner === agentId) {
        this.#claims.delete(key);
        changed = true;
      }
    }
    for (const hypothesis of this.#hypotheses.values()) {
      if (hypothesis.assignedAgentId === agentId && hypothesis.status === "testing") {
        hypothesis.status = "queued";
        delete hypothesis.assignedAgentId;
        changed = true;
      }
    }
    if (this.#allocations.delete(agentId)) changed = true;
    if (changed) this.#changed();
  }

  assign(agentId: string, limit = 3): WorkAssignment {
    if (!Number.isInteger(limit) || limit < 1) throw new Error("Assignment limit must be positive");

    const candidates = this.#candidates();
    const retained = candidates.filter((candidate) => this.#claims.get(candidate.key) === agentId);
    const available = candidates.filter((candidate) => !this.#claims.has(candidate.key));
    const selected = [...retained, ...available].slice(0, limit);
    for (const candidate of selected) {
      this.#claims.set(candidate.key, agentId);
      if (candidate.hypothesisId) {
        const hypothesis = this.#hypotheses.get(candidate.hypothesisId);
        if (hypothesis && hypothesis.status === "queued") {
          hypothesis.status = "testing";
          hypothesis.assignedAgentId = agentId;
        }
      }
    }

    const budget = this.#allocate(agentId, selected.length > 0);
    const uncoveredRouteCount = [...this.#operations].filter(
      ([operation]) => !this.#tested.has(operation),
    ).length;
    const evidenceSignals = [...this.#tested.entries()].flatMap(([operation, requests]) => {
      const modes = new Set(requests.map(({ actorId }) => actorId));
      if (modes.size >= this.#actorIds.length) return [];
      const latest = requests.at(-1)!;
      const untested = this.#actorIds.filter((actorId) => !modes.has(actorId));
      return [
        `${operation} returned ${latest.status} as ${latest.actorId}; ${untested.join(", ")} remain untested`,
      ];
    });
    const assignedHypotheses = [...this.#hypotheses.values()].filter(
      ({ assignedAgentId }) => assignedAgentId === agentId,
    );
    const specialty = this.#specialists.get(agentId)?.specialty;
    this.#changed();

    return {
      agentId,
      tasks: selected.map(({ key: _key, priority: _priority, ...task }) => task),
      uncoveredRouteCount,
      evidenceSignals,
      hypotheses: assignedHypotheses.map(cloneHypothesis),
      ...(specialty ? { specialty } : {}),
      budget,
    };
  }

  planSpecialists(limit = 2): SpecialistPlan[] {
    if (!Number.isInteger(limit) || limit < 0)
      throw new Error("Specialist limit must be non-negative");
    if (limit === 0) return [];
    const queued = [...this.#hypotheses.values()]
      .filter(({ status, confidence }) => status === "queued" && confidence >= 0.5)
      .sort((left, right) => right.confidence - left.confidence || left.id.localeCompare(right.id));
    const bySpecialty = new Map<SpecialistKind, CoordinatorHypothesis[]>();
    for (const hypothesis of queued) {
      const group = bySpecialty.get(hypothesis.specialty) ?? [];
      group.push(hypothesis);
      bySpecialty.set(hypothesis.specialty, group);
    }

    const plans: SpecialistPlan[] = [];
    for (const [specialty, hypotheses] of bySpecialty) {
      if (plans.length >= limit || this.#availableBudget() <= 0) break;
      const agentId = `specialist-${++this.#specialistSequence}`;
      const requestBudget = Math.max(
        1,
        Math.min(
          hypotheses.length * 2,
          Math.ceil(this.#availableBudget() / (limit - plans.length)),
        ),
      );
      const plan: SpecialistPlan = {
        agentId,
        specialty,
        focus: `${specialty} hypotheses: ${hypotheses.map(({ title }) => title).join("; ")}`,
        hypothesisIds: hypotheses.map(({ id }) => id),
        requestBudget,
      };
      this.#specialists.set(agentId, plan);
      this.#allocations.set(agentId, { allocated: requestBudget, used: 0 });
      for (const hypothesis of hypotheses) {
        hypothesis.status = "testing";
        hypothesis.assignedAgentId = agentId;
      }
      plans.push(plan);
    }
    if (plans.length > 0) this.#changed();
    return plans.map((plan) => ({ ...plan, hypothesisIds: [...plan.hypothesisIds] }));
  }

  focusFor(agentId: string): string | undefined {
    return this.#specialists.get(agentId)?.focus;
  }

  snapshot(): CoordinatorSnapshot {
    const workers = Object.fromEntries(
      [...this.#allocations].map(([agentId, allocation]) => [agentId, workerBudget(allocation)]),
    );
    const allocated = Object.values(workers).reduce((total, budget) => total + budget.remaining, 0);
    return {
      revision: this.#revision,
      coverage: this.#coverage(),
      hypotheses: [...this.#hypotheses.values()].map(cloneHypothesis),
      debriefs: [...this.#debriefs.values()].map((debrief) => ({
        ...debrief,
        hypotheses: debrief.hypotheses.map((item) => ({ ...item })),
      })),
      specialists: [...this.#specialists.values()].map((plan) => ({
        ...plan,
        hypothesisIds: [...plan.hypothesisIds],
      })),
      validationQueue: [...this.#validationQueue.values()].map((item) => ({ ...item })),
      budget: {
        total: this.#requestBudget ?? null,
        consumed: this.#requestsConsumed,
        allocated,
        available:
          this.#requestBudget === undefined
            ? null
            : Math.max(0, this.#requestBudget - this.#requestsConsumed - allocated),
        workers,
      },
    };
  }

  #candidates(): Candidate[] {
    const candidates: Candidate[] = [];
    for (const [operation, { method, route }] of this.#operations) {
      const requests = this.#tested.get(operation) ?? [];
      const testedModes = new Set(requests.map(({ actorId }) => actorId));
      if (requests.length === 0) {
        const actorId =
          this.#actorIds.find((candidate) => candidate !== actorIds.anonymous) ??
          actorIds.anonymous;
        candidates.push({
          key: taskKey(operation, actorId),
          route,
          method,
          actorId,
          source: "uncovered-surface",
          priority: 80,
          reason: "No explorer has tested this discovered operation yet.",
        });
        continue;
      }

      if (testedModes.size < this.#actorIds.length) {
        const latest = requests.at(-1)!;
        const actorId = this.#actorIds.find((candidate) => !testedModes.has(candidate));
        if (!actorId) continue;
        const success = latest.status >= 200 && latest.status < 300;
        const hypothesis = this.#evidenceHypothesis(operation);
        candidates.push({
          key: taskKey(operation, actorId),
          route,
          method,
          actorId,
          source: "incoming-evidence",
          priority: success ? 100 : 90,
          reason: success
            ? `${latest.actorId} access succeeded; test the ${actorId} boundary.`
            : `${latest.actorId} access returned ${latest.status}; test ${actorId} to map the boundary.`,
          ...(hypothesis ? { hypothesisId: hypothesis.id } : {}),
        });
      }
    }

    return candidates.sort((left, right) => {
      const leftFinding = this.#findings.has(operationKey(left.method, left.route)) ? 1 : 0;
      const rightFinding = this.#findings.has(operationKey(right.method, right.route)) ? 1 : 0;
      return (
        leftFinding - rightFinding ||
        right.priority - left.priority ||
        left.route.localeCompare(right.route)
      );
    });
  }

  #operationForRequest(method: string, path: string): string | undefined {
    const normalized = safeCoordinatorKey(path);
    if (!normalized) return undefined;
    const normalizedMethod = method.toUpperCase();
    const exact = operationKey(normalizedMethod, normalized);
    if (this.#operations.has(exact)) return exact;

    const matching = [...this.#operations].filter(([, candidate]) => {
      const template = safeCoordinatorKey(candidate.route);
      return (
        candidate.method === normalizedMethod && template && routeMatches(template, normalized)
      );
    });
    matching.sort(
      ([, left], [, right]) => routeSpecificity(right.route) - routeSpecificity(left.route),
    );
    return matching[0]?.[0] ?? exact;
  }

  #updateEvidenceHypothesis(operation: string, requests: TestedRequest[]): void {
    const testedModes = new Set(requests.map(({ actorId }) => actorId));
    const existing = this.#evidenceHypothesis(operation);
    if (testedModes.size > 1) {
      if (existing && existing.status !== "supported") {
        existing.status = "rejected";
        existing.evidenceSignals.push("Both access modes have now been tested.");
      }
      return;
    }
    if (existing) return;
    const candidate = this.#operations.get(operation);
    if (!candidate || this.#actorIds.length < 2) return;
    const latest = requests.at(-1)!;
    const nextActorId = this.#actorIds.find((actorId) => !testedModes.has(actorId));
    if (!nextActorId) return;
    const hypothesis: CoordinatorHypothesis = {
      id: `hypothesis-${++this.#hypothesisSequence}`,
      title: `Test the opposite access boundary for ${operation}`,
      method: candidate.method,
      route: candidate.route,
      specialty: latest.actorId === actorIds.anonymous ? "authorization" : "authentication",
      status: "queued",
      confidence: latest.status >= 200 && latest.status < 300 ? 0.75 : 0.6,
      rationale: `${latest.actorId} access returned ${latest.status}, while ${nextActorId} remains unknown.`,
      nextStep: `Repeat ${operation} as ${nextActorId}.`,
      proposedBy: "coordinator",
      evidenceSignals: [`${latest.status} observed by ${latest.agentId}`],
    };
    this.#hypotheses.set(hypothesis.id, hypothesis);
  }

  #evidenceHypothesis(operation: string): CoordinatorHypothesis | undefined {
    return [...this.#hypotheses.values()].find(
      (hypothesis) =>
        operationKey(hypothesis.method, hypothesis.route) === operation &&
        hypothesis.proposedBy === "coordinator" &&
        hypothesis.status !== "rejected",
    );
  }

  #recordHypothesis(agentId: string, input: HypothesisInput): void {
    const canonicalRoute = safeCoordinatorKey(input.route);
    if (!canonicalRoute || !Number.isFinite(input.confidence)) return;
    const method = (input.method ?? "GET").toUpperCase();
    const duplicate = [...this.#hypotheses.values()].find(
      (hypothesis) =>
        hypothesis.method === method &&
        safeCoordinatorKey(hypothesis.route) === canonicalRoute &&
        hypothesis.specialty === input.specialty &&
        hypothesis.title.toLowerCase() === input.title.toLowerCase(),
    );
    if (duplicate) {
      duplicate.confidence = Math.max(duplicate.confidence, clampConfidence(input.confidence));
      duplicate.rationale = input.rationale;
      duplicate.nextStep = input.nextStep;
      duplicate.evidenceSignals.push(`Reinforced by ${agentId}'s debrief.`);
      if (duplicate.status === "rejected") duplicate.status = "queued";
      return;
    }
    const hypothesis: CoordinatorHypothesis = {
      id: `hypothesis-${++this.#hypothesisSequence}`,
      title: input.title,
      method,
      route: input.route,
      specialty: input.specialty,
      status: "queued",
      confidence: clampConfidence(input.confidence),
      rationale: input.rationale,
      nextStep: input.nextStep,
      proposedBy: agentId,
      evidenceSignals: [`Proposed during ${agentId}'s debrief.`],
    };
    this.#hypotheses.set(hypothesis.id, hypothesis);
  }

  #allocate(agentId: string, hasWork: boolean): WorkerBudget {
    const existing = this.#allocations.get(agentId);
    if (existing) return workerBudget(existing);
    if (!hasWork) return { allocated: 0, used: 0, remaining: 0 };
    const available = this.#availableBudget();
    const activeWorkers = [...this.#allocations.values()].filter(
      ({ allocated, used }) => allocated > used,
    ).length;
    const slots = Math.max(1, this.#expectedWorkers - activeWorkers);
    const allocated =
      this.#requestBudget === undefined ? 3 : Math.max(0, Math.ceil(available / slots));
    const allocation = { allocated, used: 0 };
    this.#allocations.set(agentId, allocation);
    return workerBudget(allocation);
  }

  #availableBudget(): number {
    if (this.#requestBudget === undefined) return Number.MAX_SAFE_INTEGER;
    const reserved = [...this.#allocations.values()].reduce(
      (total, allocation) => total + Math.max(0, allocation.allocated - allocation.used),
      0,
    );
    return Math.max(0, this.#requestBudget - this.#requestsConsumed - reserved);
  }

  #coverage(): CoordinatorCoverage {
    const testedOperations = [...this.#operations].filter(([operation]) =>
      this.#tested.has(operation),
    ).length;
    const testedAccessModes = [...this.#operations].reduce((total, [operation]) => {
      const modes = new Set((this.#tested.get(operation) ?? []).map(({ actorId }) => actorId));
      return total + modes.size;
    }, 0);
    const discoveredOperations = this.#operations.size;
    const totalAccessModes = discoveredOperations * this.#actorIds.length;
    return {
      discoveredOperations,
      testedOperations,
      operationCoverage: discoveredOperations === 0 ? 0 : testedOperations / discoveredOperations,
      testedAccessModes,
      totalAccessModes,
      accessModeCoverage: totalAccessModes === 0 ? 0 : testedAccessModes / totalAccessModes,
    };
  }

  #changed(): void {
    this.#revision += 1;
    this.#onChange?.(this.snapshot());
  }
}

function cloneHypothesis(hypothesis: CoordinatorHypothesis): CoordinatorHypothesis {
  return { ...hypothesis, evidenceSignals: [...hypothesis.evidenceSignals] };
}

function workerBudget(allocation: MutableWorkerBudget): WorkerBudget {
  return {
    allocated: allocation.allocated,
    used: allocation.used,
    remaining: Math.max(0, allocation.allocated - allocation.used),
  };
}

function clampConfidence(confidence: number): number {
  return Math.min(1, Math.max(0, confidence));
}

function taskKey(operation: string, actorId: ActorId): string {
  return `${operation}:${actorId}`;
}

function uniqueActorIds(configured: readonly ActorId[]): readonly ActorId[] {
  return [...new Set([actorIds.anonymous, ...configured])];
}

function operationKey(method: string, route: string): string {
  return `${method.toUpperCase()} ${route}`;
}

function safeNormalizeEndpoint(endpoint: string): string | undefined {
  try {
    return normalizeEndpoint(endpoint);
  } catch {
    return undefined;
  }
}

function safeCoordinatorKey(endpoint: string): string | undefined {
  try {
    const url = new URL(endpoint, "http://scope.invalid");
    const path = normalizeEndpoint(url.pathname);
    url.searchParams.sort();
    return `${path}${url.search}`;
  } catch {
    return undefined;
  }
}

function routeMatches(route: string, request: string): boolean {
  const routeUrl = new URL(route, "http://scope.invalid");
  const requestUrl = new URL(request, "http://scope.invalid");
  const routeSegments = routeUrl.pathname.split("/").map(decodeURIComponent);
  const requestSegments = requestUrl.pathname.split("/").map(decodeURIComponent);
  if (
    routeSegments.length !== requestSegments.length ||
    !routeSegments.every(
      (segment, index) => isPlaceholder(segment) || segment === requestSegments[index],
    )
  ) {
    return false;
  }

  const routeParameters = [...routeUrl.searchParams];
  const requestParameters = [...requestUrl.searchParams];
  return (
    routeParameters.length === requestParameters.length &&
    routeParameters.every(([name, value], index) => {
      const requestParameter = requestParameters[index];
      return (
        requestParameter !== undefined &&
        name === requestParameter[0] &&
        (isPlaceholder(value) || value === requestParameter[1])
      );
    })
  );
}

function routeSpecificity(route: string): number {
  return route
    .split("/")
    .filter(Boolean)
    .reduce((score, segment) => score + (segment === "{id}" ? 0 : 1), 0);
}

function isPlaceholder(value: string): boolean {
  return /^(?:<[^>]+>|\{[^}]+\}|:[A-Za-z_$][\w$]*)$/.test(value);
}

/** @deprecated Use PersistentCoordinator. */
export { PersistentCoordinator as AdaptiveCoordinator };
