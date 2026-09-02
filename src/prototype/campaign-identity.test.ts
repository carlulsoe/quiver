import { describe, expect, it } from "vitest";
import { createCampaignIdentity } from "./campaign-identity.ts";

describe("campaign identity", () => {
  it("is stable across object key ordering", () => {
    const target = new URL("http://127.0.0.1:8888/api");
    const profile = {
      id: "stable-profile",
      displayName: "Stable profile",
      objective: "Bind equivalent campaign inputs.",
    };

    const left = createCampaignIdentity({
      target,
      profile,
      requestBudget: 30,
      explorerCount: 2,
      openApi: { info: { version: "1", title: "API" }, paths: {} },
    });
    const right = createCampaignIdentity({
      target,
      profile,
      requestBudget: 30,
      explorerCount: 2,
      openApi: { paths: {}, info: { title: "API", version: "1" } },
    });

    expect(left).toEqual(right);
  });

  it("changes when safety-relevant campaign inputs change", () => {
    const target = new URL("http://127.0.0.1:8888/");
    const base = {
      target,
      requestBudget: 30,
      explorerCount: 1,
      profile: {
        id: "bounded-profile",
        displayName: "Bounded profile",
        objective: "Bind safety settings.",
        maximumImpactLevel: "observation" as const,
      },
    };

    const original = createCampaignIdentity(base);
    const changed = createCampaignIdentity({
      ...base,
      profile: { ...base.profile, maximumImpactLevel: "bounded" },
    });

    expect(changed.configurationFingerprint).not.toBe(original.configurationFingerprint);
    expect(
      createCampaignIdentity({ ...base, requestBudget: 31 }).configurationFingerprint,
    ).not.toBe(original.configurationFingerprint);
  });

  it("requires an explicit binding for callback-owned closed-over values", () => {
    const target = new URL("http://127.0.0.1:8888/");
    const identity = (closedValue: string, callbackConfigurationFingerprint?: string) =>
      createCampaignIdentity({
        target,
        requestBudget: 6,
        explorerCount: 1,
        profile: callbackProfile(closedValue, callbackConfigurationFingerprint),
      });

    const firstUnbound = identity("first");
    const secondUnbound = identity("second");
    expect(firstUnbound.configurationFingerprint).toBe(secondUnbound.configurationFingerprint);
    expect(firstUnbound.resumable).toBe(false);

    const firstBound = identity("first", "callback-config:first");
    const secondBound = identity("second", "callback-config:second");
    expect(firstBound.resumable).toBe(true);
    expect(firstBound.configurationFingerprint).not.toBe(secondBound.configurationFingerprint);
  });
});

function callbackProfile(closedValue: string, callbackConfigurationFingerprint?: string) {
  return {
    id: "callback-profile",
    displayName: "Callback profile",
    objective: "Bind closed-over callback configuration.",
    authenticate: async () => ({ authContext: closedValue }),
    ...(callbackConfigurationFingerprint ? { callbackConfigurationFingerprint } : {}),
  };
}
