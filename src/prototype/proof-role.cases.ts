import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import { actorIds } from "./sessions.ts";
import { finding, identities, observation } from "./proof-test-helpers.ts";

describe("deterministic role proof", () => {
  it("proves missing function-level authorization with a cross-role differential", () => {
    const bypass = finding({
      fingerprint: "broken-function-authorization:GET:/admin/audit",
      category: "broken-function-authorization",
      endpoint: "/admin/audit",
      reproduction: [
        { path: "/admin/audit?range=today", actorId: actorIds.administrator },
        { path: "/admin/audit?range=today", actorId: actorIds.userA },
      ],
      proof: {
        type: "role-privilege-differential",
        authorizedRequestIndex: 0,
        lessPrivilegedRequestIndex: 1,
        evidencePointers: ["/report/id"],
      },
    });
    const context = {
      identities,
      protectedOperations: [
        {
          method: "GET" as const,
          path: "/admin/audit",
          authorizedActors: [actorIds.administrator],
        },
      ],
    };
    const observations = [
      observation(
        "/admin/audit?range=today",
        { report: { id: "audit-today" } },
        { actorId: actorIds.administrator },
      ),
      observation(
        "/admin/audit?range=today",
        { report: { id: "audit-today" } },
        { actorId: actorIds.userA },
      ),
    ];

    expect(evaluateProof(bypass, observations, context)).toMatchObject({
      passed: true,
      predicate: "role-privilege-differential",
    });
    expect(
      evaluateProof(
        {
          ...bypass,
          reproduction: [
            { ...bypass.reproduction[0]!, actorId: actorIds.userB },
            bypass.reproduction[1]!,
          ],
        },
        [{ ...observations[0]!, actorId: actorIds.userB }, observations[1]!],
        {
          identities,
          protectedOperations: [
            {
              method: "GET",
              path: "/admin/audit",
              authorizedActors: [actorIds.userB],
            },
          ],
        },
      ).passed,
    ).toBe(false);
  });

  it("proves a cross-role business action only for a state-changing protected operation", () => {
    const businessAction = finding({
      fingerprint: "business-logic:POST:/admin/reindex",
      category: "business-logic",
      endpoint: "/admin/reindex",
      method: "POST",
      reproduction: [
        {
          path: "/admin/reindex",
          method: "POST",
          body: '{"scope":"catalog"}',
          actorId: actorIds.administrator,
        },
        {
          path: "/admin/reindex",
          method: "POST",
          body: '{"scope":"catalog"}',
          actorId: actorIds.userA,
        },
      ],
      proof: {
        type: "role-privilege-differential",
        authorizedRequestIndex: 0,
        lessPrivilegedRequestIndex: 1,
        evidencePointers: ["/job/type"],
      },
    });
    const context = {
      identities,
      protectedOperations: [
        {
          method: "POST" as const,
          path: "/admin/reindex",
          authorizedActors: [actorIds.administrator],
        },
      ],
    };
    const observations = [
      observation(
        "/admin/reindex",
        { job: { type: "catalog-reindex" } },
        { actorId: actorIds.administrator, method: "POST" },
      ),
      observation(
        "/admin/reindex",
        { job: { type: "catalog-reindex" } },
        { actorId: actorIds.userA, method: "POST" },
      ),
    ];

    expect(evaluateProof(businessAction, observations, context).passed).toBe(true);
    expect(
      evaluateProof(
        {
          ...businessAction,
          method: "GET",
          reproduction: businessAction.reproduction.map((request) => ({
            ...request,
            method: "GET" as const,
            body: undefined,
          })),
        },
        observations.map((item) => ({ ...item, method: "GET" as const })),
        {
          identities,
          protectedOperations: [
            {
              method: "GET",
              path: "/admin/reindex",
              authorizedActors: [actorIds.administrator],
            },
          ],
        },
      ).passed,
    ).toBe(false);
  });
});
