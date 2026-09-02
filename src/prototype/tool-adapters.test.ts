import { describe, expect, it, vi } from "vitest";
import { createBoundedToolAdapters, NON_REST_AGENT_TOOL_NAMES } from "./tool-adapters.ts";

describe("bounded non-REST tool adapters", () => {
  it("derives browser execution details from a target-owned policy", async () => {
    const observeBrowserEffect = vi.fn(async (input) => ({
      probeId: input.probeId,
      path: input.path,
      kind: input.kind,
      value: input.marker,
    }));
    const recordBrowserEffect = vi.fn();
    const adapters = createBoundedToolAdapters({
      target: {
        assertImpactLevel: vi.fn(),
        mapAttackSurface: vi.fn(),
        observeBrowserEffect,
      },
      profile: {
        id: "bounded-adapter",
        displayName: "Bounded adapter",
        objective: "Test an adapter.",
        proofPolicies: [
          {
            kind: "browser-effect",
            id: "dialog-proof",
            category: "cross-site-scripting",
            description: "Observe a target-owned dialog marker.",
            workflow: "dom",
            endpoint: "/preview",
            method: "GET",
            markerPattern: "^issued-marker$",
            pagePath: "/preview?payload=old",
            payloadTemplate: "<script>alert('{{challenge}}')</script>",
            challenge: {
              location: "query",
              parameter: "payload",
              template: "<script>alert('{{challenge}}')</script>",
            },
            pageChallenge: {
              location: "query",
              parameter: "payload",
              template: "<script>alert('{{challenge}}')</script>",
            },
            submissionActorId: "anonymous",
            pageActorId: "anonymous",
            effect: "dialog",
            requestBudget: 2,
          },
        ],
      },
      artifacts: {
        issueOastProbe: vi.fn(),
        waitForOastCallback: vi.fn(),
        issueBrowserProbe: vi.fn(),
        browserProbe: vi.fn(() => ({ probeId: "probe-1", marker: "issued-marker" })),
        recordBrowserEffect,
      },
    });

    await adapters.browser.observe({ policyId: "dialog-proof", probeId: "probe-1" });

    expect(observeBrowserEffect).toHaveBeenCalledWith({
      probeId: "probe-1",
      marker: "issued-marker",
      path: "/preview?payload=%3Cscript%3Ealert%28%27issued-marker%27%29%3C%2Fscript%3E",
      kind: "dialog",
      actorId: "anonymous",
      requestBudget: 2,
    });
    expect(recordBrowserEffect).toHaveBeenCalledOnce();
  });

  it("rejects arbitrary browser policies and exposes no shell capability", async () => {
    const adapters = createBoundedToolAdapters({
      target: {
        assertImpactLevel: vi.fn(),
        mapAttackSurface: vi.fn(),
        observeBrowserEffect: vi.fn(),
      },
      profile: { id: "none", displayName: "None", objective: "None" },
      artifacts: {
        issueOastProbe: vi.fn(),
        waitForOastCallback: vi.fn(),
        issueBrowserProbe: vi.fn(),
        browserProbe: vi.fn(),
        recordBrowserEffect: vi.fn(),
      },
    });

    await expect(
      adapters.browser.observe({ policyId: "invented", probeId: "probe-1" }),
    ).rejects.toThrow("Unknown browser-effect proof policy");
    expect(NON_REST_AGENT_TOOL_NAMES).not.toContain("bash");
    expect(NON_REST_AGENT_TOOL_NAMES).not.toContain("shell");
    expect(Object.keys(adapters)).toEqual(["discovery", "oast", "browser"]);
  });
});
