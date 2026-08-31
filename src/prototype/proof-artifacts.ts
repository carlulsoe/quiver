import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import type { BrowserEffectEvidence, OastCallbackEvidence, ProofArtifacts } from "./state.ts";

export interface ProofArtifactCheckpoint {
  browserEffects: number;
  oastCallbacks: number;
}

export interface OastProbe {
  probeId: string;
  token: string;
  url: string;
}

export interface BrowserProbe {
  probeId: string;
  marker: string;
}

export interface ProofArtifactStoreOptions {
  bindHost?: string;
  advertisedHost?: string;
}

/** Owns fresh, campaign-local execution artifacts. It never accepts arbitrary external hosts. */
export class ProofArtifactStore implements AsyncDisposable {
  readonly #browserEffects: BrowserEffectEvidence[] = [];
  readonly #oastCallbacks: OastCallbackEvidence[] = [];
  readonly #issuedOastTokens = new Map<string, string>();
  readonly #issuedBrowserMarkers = new Map<string, string>();
  readonly #bindHost: string;
  readonly #advertisedHost: string;
  #server?: ReturnType<typeof Bun.serve>;

  constructor(options: ProofArtifactStoreOptions = {}) {
    this.#bindHost = validatedHost(
      options.bindHost ?? process.env.QUIVER_OAST_BIND_HOST ?? "127.0.0.1",
      "OAST bind host",
    );
    this.#advertisedHost = validatedHost(
      options.advertisedHost ?? process.env.QUIVER_OAST_ADVERTISED_HOST ?? "127.0.0.1",
      "OAST advertised host",
    );
  }

  startOastListener(): void {
    if (this.#server) return;
    this.#server = Bun.serve({
      hostname: this.#bindHost,
      port: 0,
      fetch: (request) => this.#receiveCallback(request),
    });
  }

  issueOastProbe(): OastProbe {
    this.startOastListener();
    const probeId = randomUUID();
    const token = randomUUID();
    this.#issuedOastTokens.set(probeId, token);
    return {
      probeId,
      token,
      url: `http://${urlHost(this.#advertisedHost)}:${this.#server!.port}/callback/${probeId}/${token}`,
    };
  }

  issueBrowserProbe(): BrowserProbe {
    const probeId = randomUUID();
    const marker = `QUIVER-BROWSER-${randomUUID()}`;
    this.#issuedBrowserMarkers.set(probeId, marker);
    return { probeId, marker };
  }

  async waitForOastCallback(
    probeId: string,
    token: string,
    timeoutMs = 500,
  ): Promise<OastCallbackEvidence | undefined> {
    if (this.#issuedOastTokens.get(probeId) !== token) return undefined;
    const deadline = performance.now() + timeoutMs;
    do {
      const callback = this.#oastCallbacks.find(
        (candidate) => candidate.probeId === probeId && candidate.token === token,
      );
      if (callback) return { ...callback };
      await new Promise((resolve) => setTimeout(resolve, 25));
    } while (performance.now() < deadline);
    return undefined;
  }

  recordBrowserEffect(evidence: BrowserEffectEvidence): void {
    if (this.#issuedBrowserMarkers.get(evidence.probeId) === evidence.value) {
      this.#browserEffects.push({ ...evidence });
    }
  }

  checkpoint(): ProofArtifactCheckpoint {
    return {
      browserEffects: this.#browserEffects.length,
      oastCallbacks: this.#oastCallbacks.length,
    };
  }

  artifactsSince(checkpoint: ProofArtifactCheckpoint): ProofArtifacts {
    return {
      browserEffects: this.#browserEffects.slice(checkpoint.browserEffects).map((item) => ({
        ...item,
      })),
      oastCallbacks: this.#oastCallbacks.slice(checkpoint.oastCallbacks).map((item) => ({
        ...item,
      })),
    };
  }

  snapshot(): ProofArtifacts {
    return this.artifactsSince({ browserEffects: 0, oastCallbacks: 0 });
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.#server?.stop(true);
    this.#server = undefined;
  }

  #receiveCallback(request: Request): Response {
    const url = new URL(request.url);
    const match = url.pathname.match(/^\/callback\/([^/]+)\/([^/]+)$/);
    if (!match) return new Response("not found", { status: 404 });
    const [, probeId, token] = match;
    if (!probeId || !token || this.#issuedOastTokens.get(probeId) !== token) {
      return new Response("not found", { status: 404 });
    }
    if (this.#oastCallbacks.some((callback) => callback.probeId === probeId)) {
      return new Response(null, { status: 204 });
    }
    this.#oastCallbacks.push({
      probeId,
      token,
      protocol: "http",
      method: request.method,
      path: `${url.pathname}${url.search}`,
      observedAt: new Date().toISOString(),
    });
    return new Response(null, { status: 204 });
  }
}

function validatedHost(value: string, label: string): string {
  const host = value.trim();
  if (
    !host ||
    (!isIP(host) &&
      !/^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)*[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(
        host,
      ))
  ) {
    throw new Error(`${label} must be an IP address or hostname without a scheme or path`);
  }
  return host;
}

function urlHost(host: string): string {
  return isIP(host) === 6 ? `[${host}]` : host;
}
