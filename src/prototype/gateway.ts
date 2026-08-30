import { assessVehicleLocationBola, type HttpObservation } from "./bola.ts";

interface LoginResponse {
  token?: unknown;
}

interface VehicleResponse {
  uuid?: unknown;
}

export type HttpTransport = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export interface GatewayRequest {
  number: number;
  method: string;
  path: string;
}

export interface LocalCrapiGatewayOptions {
  target: URL;
  requestBudget: number;
  onRequest?: (request: GatewayRequest) => void;
  transport?: HttpTransport;
  timeoutMs?: number;
  maxResponseChars?: number;
}

export class RequestBudgetExceededError extends Error {
  override readonly name = "RequestBudgetExceededError";
}

export class TargetScopeError extends Error {
  override readonly name = "TargetScopeError";
}

export class LocalCrapiGateway {
  readonly #origin: string;
  readonly #requestBudget: number;
  readonly #onRequest?: (request: GatewayRequest) => void;
  readonly #transport: HttpTransport;
  readonly #timeoutMs: number;
  readonly #maxResponseChars: number;
  #requestsUsed = 0;
  #testToken?: string;

  constructor(options: LocalCrapiGatewayOptions) {
    const localHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
    if (
      !localHosts.has(options.target.hostname) ||
      !["http:", "https:"].includes(options.target.protocol)
    ) {
      throw new TargetScopeError("Only loopback HTTP(S) targets are allowed");
    }
    this.#origin = options.target.origin;
    this.#requestBudget = options.requestBudget;
    this.#onRequest = options.onRequest;
    this.#transport = options.transport ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#maxResponseChars = options.maxResponseChars ?? 12_000;
  }

  async healthcheck(): Promise<void> {
    const result = await this.get("/health", false);
    if (result.status !== 200) throw new Error(`crAPI healthcheck returned ${result.status}`);
  }

  async loginTestUser(): Promise<{ authContext: "test-user" }> {
    if (this.#testToken) return { authContext: "test-user" };

    const result = await this.#request("/identity/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "test@example.com", password: "Test!123" }),
    });
    const body = result.body as LoginResponse;
    if (result.status !== 200 || typeof body.token !== "string") {
      throw new Error(`seed-user login failed with status ${result.status}`);
    }
    this.#testToken = body.token;
    return { authContext: "test-user" };
  }

  async get(path: string, authenticated: boolean): Promise<HttpObservation> {
    if (authenticated && !this.#testToken) await this.loginTestUser();
    return this.#request(path, {
      method: "GET",
      headers:
        this.#testToken && authenticated ? { authorization: `Bearer ${this.#testToken}` } : {},
    });
  }

  async getOwnVehicleId(): Promise<string> {
    await this.loginTestUser();
    const result = await this.get("/identity/api/v2/vehicle/vehicles", true);
    const vehicles = result.body as VehicleResponse[];
    const vehicleId = vehicles[0]?.uuid;
    if (result.status !== 200 || typeof vehicleId !== "string") {
      throw new Error(`could not resolve the seeded user's vehicle: status=${result.status}`);
    }
    return vehicleId;
  }

  async reproduceBola(vehicleId: string): Promise<{
    confirmed: boolean;
    reason: ReturnType<typeof assessVehicleLocationBola>["reason"];
    evidence: string;
    facts: ReturnType<typeof assessVehicleLocationBola>["facts"];
    dashboard: HttpObservation;
    location: HttpObservation;
  }> {
    await this.loginTestUser();
    const dashboard = await this.get("/identity/api/v2/user/dashboard", true);
    const locationPath = `/identity/api/v2/vehicle/${encodeURIComponent(vehicleId)}/location`;
    const location = await this.get(locationPath, true);
    return { ...assessVehicleLocationBola(dashboard, location), dashboard, location };
  }

  async #request(path: string, init: RequestInit): Promise<HttpObservation> {
    if (!path.startsWith("/") || path.startsWith("//"))
      throw new TargetScopeError("Only origin-relative paths are allowed");
    if (this.#requestsUsed >= this.#requestBudget) {
      throw new RequestBudgetExceededError(
        `Request budget exhausted (${this.#requestsUsed}/${this.#requestBudget})`,
      );
    }

    const url = new URL(path, this.#origin);
    if (url.origin !== this.#origin) throw new TargetScopeError("Out-of-scope origin blocked");

    this.#requestsUsed += 1;
    this.#onRequest?.({
      number: this.#requestsUsed,
      method: init.method ?? "GET",
      path: `${url.pathname}${url.search}`,
    });
    const response = await this.#transport(url, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    const responseText = await response.text();
    const truncated = responseText.length > this.#maxResponseChars;
    const text = responseText.slice(0, this.#maxResponseChars);
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // Text is a valid prototype response body.
    }

    return { status: response.status, path: `${url.pathname}${url.search}`, body, truncated };
  }
}
