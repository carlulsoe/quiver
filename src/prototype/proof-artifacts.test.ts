import { describe, expect, it } from "vitest";
import { ProofArtifactStore } from "./proof-artifacts.ts";

describe("proof artifact store", () => {
  it("issues unguessable loopback probes and returns only fresh callbacks", async () => {
    await using store = new ProofArtifactStore();
    const probe = store.issueOastProbe();
    const checkpoint = store.checkpoint();

    await expect(fetch(probe.url, { method: "POST" })).resolves.toMatchObject({ status: 204 });
    await expect(fetch(probe.url, { method: "POST" })).resolves.toMatchObject({ status: 204 });

    expect(store.artifactsSince(checkpoint).oastCallbacks).toEqual([
      expect.objectContaining({
        probeId: probe.probeId,
        token: probe.token,
        protocol: "http",
        method: "POST",
      }),
    ]);
    expect(store.artifactsSince(store.checkpoint()).oastCallbacks).toEqual([]);
  });

  it("does not record callbacks for unissued tokens", async () => {
    await using store = new ProofArtifactStore();
    const probe = store.issueOastProbe();
    const invalid = probe.url.replace(probe.token, "not-issued");

    await expect(fetch(invalid)).resolves.toMatchObject({ status: 404 });
    expect(store.snapshot().oastCallbacks).toEqual([]);
  });

  it("records browser effects only for a marker issued by the store", async () => {
    await using store = new ProofArtifactStore();
    const probe = store.issueBrowserProbe();
    expect(store.browserProbe(probe.probeId)).toEqual(probe);
    expect(store.browserProbe("not-issued")).toBeUndefined();
    store.recordBrowserEffect({
      probeId: probe.probeId,
      path: "/result",
      kind: "dialog",
      value: "forged",
    });
    store.recordBrowserEffect({
      probeId: probe.probeId,
      path: "/result",
      kind: "dialog",
      value: probe.marker,
    });

    expect(store.snapshot().browserEffects).toEqual([
      { probeId: probe.probeId, path: "/result", kind: "dialog", value: probe.marker },
    ]);
  });

  it("separates the listener bind host from a validated Docker-reachable advertised host", async () => {
    await using store = new ProofArtifactStore({
      bindHost: "127.0.0.1",
      advertisedHost: "host.docker.internal",
    });

    expect(store.issueOastProbe().url).toMatch(/^http:\/\/host\.docker\.internal:\d+\/callback\//);
    expect(
      () => new ProofArtifactStore({ advertisedHost: "https://attacker.example/path" }),
    ).toThrow(/hostname without a scheme or path/);
  });
});
