import { describe, expect, it } from "vitest";
import { CampaignLedger } from "./campaign-ledger.ts";
import type { FindingInput } from "./state.ts";

const finding: FindingInput = {
  agentId: "explorer-1",
  title: "Object leak",
  category: "broken-object-authorization",
  endpoint: "/api/items/42",
  resource: "42",
  rationale: "A different user's object was returned.",
  reproduction: [{ path: "/api/items/42", authenticated: true }],
};

describe("campaign ledger", () => {
  it("coalesces concurrent duplicate requests and reuses the observation", async () => {
    const ledger = new CampaignLedger();
    let networkRequests = 0;
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const execute = async () => {
      networkRequests += 1;
      await blocked;
      return { status: 200, path: "/api/items/42", body: { id: 42 } };
    };

    const first = ledger.request(
      { agentId: "explorer-1", path: "/api/items/42", authenticated: true },
      execute,
    );
    const second = ledger.request(
      { agentId: "explorer-2", path: "/api/items/42", authenticated: true },
      execute,
    );
    release();

    await expect(first).resolves.toMatchObject({ reused: false });
    await expect(second).resolves.toMatchObject({ reused: true });
    expect(networkRequests).toBe(1);
    expect(ledger.snapshot().testedRequests).toEqual([
      {
        agentId: "explorer-1",
        path: "/api/items/42",
        authenticated: true,
        status: 200,
      },
    ]);
  });

  it("treats anonymous and authenticated requests as separate tests", async () => {
    const ledger = new CampaignLedger();
    let networkRequests = 0;
    const execute = async () => ({
      status: ++networkRequests === 1 ? 401 : 200,
      path: "/api/me",
      body: {},
    });

    await ledger.request({ agentId: "explorer-1", path: "/api/me", authenticated: false }, execute);
    await ledger.request({ agentId: "explorer-1", path: "/api/me", authenticated: true }, execute);

    expect(networkRequests).toBe(2);
    expect(ledger.snapshot().testedRequests).toHaveLength(2);
  });

  it("shares accepted finding fingerprints and rejects duplicates", () => {
    const ledger = new CampaignLedger();

    expect(ledger.recordFinding(finding)).toMatchObject({ accepted: true });
    expect(
      ledger.recordFinding({ ...finding, agentId: "explorer-2", resource: "99" }),
    ).toMatchObject({ accepted: false });
    expect(ledger.snapshot().findings).toEqual([
      {
        agentId: "explorer-1",
        fingerprint: "broken-object-authorization:GET:/api/items/{id}",
        title: "Object leak",
        endpoint: "/api/items/42",
      },
    ]);
  });

  it("allows a failed request to be retried", async () => {
    const ledger = new CampaignLedger();
    const request = { agentId: "explorer-1", path: "/api/flaky", authenticated: false };

    await expect(
      ledger.request(request, async () => {
        throw new Error("temporary failure");
      }),
    ).rejects.toThrow("temporary failure");
    await expect(
      ledger.request(request, async () => ({ status: 200, path: "/api/flaky", body: "ok" })),
    ).resolves.toMatchObject({ reused: false, observation: { status: 200 } });
  });
});
