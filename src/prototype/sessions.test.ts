import { describe, expect, it } from "vitest";
import { actorIds, InMemorySessions } from "./sessions.ts";

describe("actor sessions", () => {
  it("resolves anonymous, two ordinary principals, and a privileged principal independently", async () => {
    const sessions = new InMemorySessions();
    sessions.set(actorIds.ordinary, { headers: { authorization: "Bearer ordinary" } });
    sessions.set(actorIds.second, { headers: { authorization: "Bearer second" } });
    sessions.set(actorIds.privileged, {
      headers: { authorization: "Bearer privileged" },
      browserState: { localStorage: { role: "admin" } },
    });

    await expect(sessions.acquire(actorIds.anonymous)).resolves.toEqual({
      actorId: actorIds.anonymous,
      headers: {},
    });
    await expect(sessions.acquire(actorIds.ordinary)).resolves.toMatchObject({
      actorId: actorIds.ordinary,
      headers: { authorization: "Bearer ordinary" },
    });
    await expect(sessions.acquire(actorIds.second)).resolves.toMatchObject({
      actorId: actorIds.second,
      headers: { authorization: "Bearer second" },
    });
    await expect(sessions.browserState(actorIds.privileged)).resolves.toMatchObject({
      headers: { authorization: "Bearer privileged" },
      localStorage: { role: "admin" },
    });
  });

  it("does not leak mutable session material between callers or principals", async () => {
    const sessions = new InMemorySessions();
    sessions.set(actorIds.userA, {
      headers: { authorization: "Bearer user-a" },
      browserState: {
        localStorage: { principal: "user-a" },
        cookies: [{ name: "session", value: "cookie-a", domain: "localhost", path: "/" }],
      },
    });
    sessions.set(actorIds.userB, {
      headers: { authorization: "Bearer user-b" },
      browserState: {
        localStorage: { principal: "user-b" },
        cookies: [{ name: "session", value: "cookie-b", domain: "localhost", path: "/" }],
      },
    });

    const acquiredA = await sessions.acquire(actorIds.userA);
    const browserA = await sessions.browserState(actorIds.userA);
    acquiredA.headers.authorization = "Bearer overwritten";
    browserA.localStorage!.principal = "overwritten";
    browserA.cookies![0]!.value = "overwritten";

    await expect(sessions.acquire(actorIds.userA)).resolves.toMatchObject({
      headers: { authorization: "Bearer user-a" },
    });
    await expect(sessions.browserState(actorIds.userA)).resolves.toMatchObject({
      localStorage: { principal: "user-a" },
      cookies: [{ value: "cookie-a" }],
    });
    await expect(sessions.browserState(actorIds.userB)).resolves.toMatchObject({
      headers: { authorization: "Bearer user-b" },
      localStorage: { principal: "user-b" },
      cookies: [{ value: "cookie-b" }],
    });
  });
});
