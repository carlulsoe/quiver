import { describe, expect, it, vi } from "vitest";
import { createBoundedToolAdapters, NON_REST_AGENT_TOOL_NAMES } from "./tool-adapters.ts";

describe("bounded non-REST tool adapters", () => {
  it("exports the exhaustive agent-visible non-REST tool inventory", () => {
    expect(NON_REST_AGENT_TOOL_NAMES).toEqual([
      "map_attack_surface",
      "create_oast_probe",
      "poll_oast_probe",
      "create_browser_probe",
      "observe_browser_effect",
      "observe_browser_state_transition",
    ]);
  });

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
        observeBrowserStateTransition: vi.fn(),
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
        recordBrowserStateTransition: vi.fn(),
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

  it("derives browser state-transition execution from a target-owned policy", async () => {
    const observeBrowserStateTransition = vi.fn(async (input) => ({
      policyId: input.policyId,
      sourceOrigin: input.sourceOrigin,
      sourcePath: input.sourcePath,
      targetPath: input.targetPath,
      method: input.method,
      status: 302,
    }));
    const recordBrowserStateTransition = vi.fn();
    const adapters = createBoundedToolAdapters({
      target: {
        assertImpactLevel: vi.fn(),
        mapAttackSurface: vi.fn(),
        observeBrowserEffect: vi.fn(),
        observeBrowserStateTransition,
      },
      profile: {
        id: "state-transition-adapter",
        displayName: "State transition adapter",
        objective: "Test an adapter.",
        proofPolicies: [
          {
            kind: "browser-state-transition",
            id: "email-csrf",
            category: "cross-site-request-forgery",
            description: "Observe a policy-owned cross-origin state transition.",
            endpoint: "/account/email",
            method: "POST",
            sourceOrigin: "http://127.0.0.1:9999",
            sourcePath: "/csrf/email",
            pageActorId: "ordinary-user",
            requestBudget: 2,
            readEndpoint: "/account",
            readMethod: "GET",
            jsonPointer: "/email",
            before: "before@example.test",
            after: "after@example.test",
          },
        ],
      },
      artifacts: {
        issueOastProbe: vi.fn(),
        waitForOastCallback: vi.fn(),
        issueBrowserProbe: vi.fn(),
        browserProbe: vi.fn(),
        recordBrowserEffect: vi.fn(),
        recordBrowserStateTransition,
      },
    });

    await adapters.browser.observeStateTransition({ policyId: "email-csrf" });

    expect(observeBrowserStateTransition).toHaveBeenCalledWith({
      policyId: "email-csrf",
      sourceOrigin: "http://127.0.0.1:9999",
      sourcePath: "/csrf/email",
      targetPath: "/account/email",
      method: "POST",
      actorId: "ordinary-user",
      requestBudget: 2,
    });
    expect(recordBrowserStateTransition).toHaveBeenCalledOnce();
  });

  it("rejects arbitrary browser policies and exposes no shell capability", async () => {
    const adapters = createBoundedToolAdapters({
      target: {
        assertImpactLevel: vi.fn(),
        mapAttackSurface: vi.fn(),
        observeBrowserEffect: vi.fn(),
        observeBrowserStateTransition: vi.fn(),
      },
      profile: { id: "none", displayName: "None", objective: "None" },
      artifacts: {
        issueOastProbe: vi.fn(),
        waitForOastCallback: vi.fn(),
        issueBrowserProbe: vi.fn(),
        browserProbe: vi.fn(),
        recordBrowserEffect: vi.fn(),
        recordBrowserStateTransition: vi.fn(),
      },
    });

    await expect(
      adapters.browser.observe({ policyId: "invented", probeId: "probe-1" }),
    ).rejects.toThrow("Unknown browser-effect proof policy");
    await expect(adapters.browser.observeStateTransition({ policyId: "invented" })).rejects.toThrow(
      "Unknown browser-state-transition proof policy",
    );
    expect(NON_REST_AGENT_TOOL_NAMES).not.toContain("bash");
    expect(NON_REST_AGENT_TOOL_NAMES).not.toContain("shell");
    expect(Object.keys(adapters)).toEqual(["discovery", "oast", "browser"]);
  });
});
