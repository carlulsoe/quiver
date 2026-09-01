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
});
