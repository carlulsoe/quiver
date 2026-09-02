import { CampaignSession } from "./campaign-session.ts";
import { createModelRouter } from "./model-routing.ts";
import { RuntimeSafetyController } from "./runtime-safety.ts";
import type { FindingInput, ValidationObservation } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";
import { ValidationExecutor } from "./validation-executor.ts";
import type { VerificationEngine, VerificationReplay } from "./verification.ts";
import { describe, expect, it } from "vitest";

describe("validation executor", () => {
  it("quarantines an exploit chain when an unexpected error follows mutation", async () => {
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => Response.json({ changed: true }),
    });
    try {
      const profile = {
        id: "post-mutation-failure",
        displayName: "Post-mutation failure",
        objective: "Quarantine partially applied exploit chains.",
        maximumImpactLevel: "state-change",
        allowedRequests: [{ method: "POST", path: "/mutate" }],
        setupRequests: [{ method: "POST", path: "/login" }],
      } satisfies TargetProfile;
      const session = new CampaignSession({
        target: new URL(server.url),
        profile,
        requestBudget: 12,
        explorerCount: 1,
      });
      session.dispatch({ type: "finding", finding: producerFinding() });
      session.dispatch({ type: "finding", finding: consumerFinding() });
      const [producer, consumer] = session.state.findings;
      session.dispatch({
        type: "exploit-chain",
        chain: {
          agentId: "explorer-1",
          title: "Produced value triggers a mutation",
          impactLevel: "state-change",
          steps: [producer!.fingerprint, consumer!.fingerprint],
          links: [
            {
              from: { fingerprint: producer!.fingerprint, requestIndex: 0, jsonPointer: "/token" },
              to: {
                fingerprint: consumer!.fingerprint,
                requestIndex: 0,
                location: "json-body",
                parameter: "token",
              },
            },
          ],
        },
      });
      let replayCount = 0;
      const verification: VerificationEngine = {
        preflight: () => {
          throw new Error("not used");
        },
        impactLevelFor: () => undefined,
        async replay(finding, target): Promise<VerificationReplay> {
          replayCount += 1;
          if (replayCount === 1) {
            await target.runProfileSetup(() =>
              target.setupRequest({ path: "/login", method: "POST" }),
            );
            expect(
              session.state.runtime.jobs.find(({ kind }) => kind === "exploit-chain")
                ?.mutationStarted,
            ).toBe(false);
          }
          if (replayCount === 2) {
            await target.request({
              path: "/mutate",
              method: "POST",
              body: "{}",
              actorId: "anonymous",
            });
            throw new Error("verification crashed after mutation");
          }
          const observation: ValidationObservation = {
            path: finding.reproduction[0]!.path,
            status: 200,
            actorId: "anonymous",
            body: { token: "fresh" },
            truncated: false,
          };
          return {
            fingerprint: finding.fingerprint,
            replayedFinding: finding,
            observations: [observation],
            artifacts: { browserEffects: [], browserStateTransitions: [], oastCallbacks: [] },
            proof: {
              predicate: finding.proof.type,
              passed: true,
              summary: "synthetic producer proof",
              checks: [],
            },
          };
        },
      };
      const executor = new ValidationExecutor({
        target: new URL(server.url),
        profile,
        session,
        coordinator: {
          recordValidation: () => undefined,
          claimValidation: () => "claimed",
          releaseValidation: () => undefined,
        },
        modelRouter: createModelRouter(),
        verification,
        runtimeSafety: new RuntimeSafetyController(),
      });

      await executor.runExploitChains();

      expect(session.state.runtime).toMatchObject({
        control: "halted",
        jobs: expect.arrayContaining([
          expect.objectContaining({
            kind: "exploit-chain",
            status: "interrupted",
            mutationStarted: true,
            error: "verification crashed after mutation",
          }),
        ]),
      });
      expect(session.state.exploitChainValidations).toHaveLength(0);
    } finally {
      server.stop(true);
    }
  });
});

function producerFinding(): FindingInput {
  return {
    agentId: "explorer-1",
    title: "Producer",
    category: "sensitive-data-exposure",
    severity: "medium",
    cwe: "CWE-200",
    endpoint: "/producer",
    resource: "producer token",
    rationale: "Producer rationale",
    impact: "Producer impact",
    mitigation: "Producer mitigation",
    reproduction: [{ path: "/producer", actorId: "anonymous" }],
    proof: { type: "internal-field-exposure", requestIndex: 0, evidencePointers: ["/token"] },
  };
}

function consumerFinding(): FindingInput {
  return {
    agentId: "explorer-1",
    title: "Consumer",
    category: "business-logic",
    severity: "high",
    cwe: "CWE-840",
    endpoint: "/mutate",
    method: "POST",
    resource: "mutable target state",
    rationale: "Consumer rationale",
    impact: "Consumer impact",
    mitigation: "Consumer mitigation",
    reproduction: [
      { path: "/mutate", method: "POST", body: '{"token":"stale"}', actorId: "anonymous" },
    ],
    proof: { type: "internal-field-exposure", requestIndex: 0, evidencePointers: ["/changed"] },
  };
}
