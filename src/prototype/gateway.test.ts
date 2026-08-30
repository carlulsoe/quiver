import { describe, expect, it } from "vitest";
import { LocalCrapiGateway, RequestBudgetExceededError, TargetScopeError } from "./gateway.ts";

describe("local crAPI gateway", () => {
  it("enforces one request budget across every target operation", async () => {
    const requested: string[] = [];
    const gateway = new LocalCrapiGateway({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      onRequest: () => {},
      transport: async (url) => {
        requested.push(String(url));
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    });

    await gateway.get("/first", false);

    await expect(gateway.get("/second", false)).rejects.toBeInstanceOf(RequestBudgetExceededError);
    expect(requested).toEqual(["http://127.0.0.1:8888/first"]);
  });

  it("rejects a non-loopback target at construction", () => {
    expect(
      () =>
        new LocalCrapiGateway({
          target: new URL("https://example.com"),
          requestBudget: 1,
        }),
    ).toThrow(TargetScopeError);
  });

  it("marks responses that were capped before agents can consume them", async () => {
    const gateway = new LocalCrapiGateway({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      maxResponseChars: 5,
      transport: async () => new Response("abcdefgh", { status: 200 }),
    });

    await expect(gateway.get("/large", false)).resolves.toMatchObject({
      body: "abcde",
      truncated: true,
    });
  });
});
