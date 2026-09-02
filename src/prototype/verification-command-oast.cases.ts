import { describe, expect, it } from "vitest";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";
import { DefaultVerificationEngine, type VerificationEngine } from "./verification.ts";
import { vulnerableAppProfile } from "../targets/vulnerableapp.ts";
import { commandInjectionFinding, injectionObservations } from "./verification-test-helpers.ts";

describe("verification command and OAST", () => {
  it("confirms command injection with a fresh computed execution challenge", async () => {
    await using artifacts = new ProofArtifactStore();
    const verification: VerificationEngine = new DefaultVerificationEngine(
      vulnerableAppProfile,
      artifacts,
      { issueIntegerChallenge: () => 654_321 },
    );
    const commandFinding = commandInjectionFinding("LEVEL_1", "vulnerableapp-command-level-1");
    expect(verification.impactLevelFor(commandFinding.reproduction[0]!)).toBe("bounded");
    expect(
      verification.preflight(commandFinding, {
        observations: injectionObservations(commandFinding, [
          { content: `ping output\nQUIVER-COMMAND-${123_456 * 17 + 31}` },
        ]),
      }),
    ).toMatchObject({
      accepted: true,
      proof: {
        passed: true,
        predicate: "command-execution-challenge",
        classification: "command-execution",
      },
    });

    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:9090/VulnerableApp/"),
      requestBudget: 1,
      maximumImpactLevel: "bounded",
      transport: async (input) => {
        const command =
          new URL(input instanceof Request ? input.url : input).searchParams.get("ipaddress") ?? "";
        const challenge = Number(command.match(/17\*(\d+)\+31/)?.[1]);
        return Response.json({ content: `QUIVER-COMMAND-${challenge * 17 + 31}` });
      },
    });
    const replay = await verification.replay(commandFinding, target);
    expect(replay).toMatchObject({
      proof: { passed: true, predicate: "command-execution-challenge" },
      replayedFinding: {
        proof: { type: "command-execution-challenge", challenge: 654_321 },
      },
    });
    expect(replay.replayedFinding.reproduction[0]?.path).toContain("654321");
    expect(replay.replayedFinding.reproduction[0]?.path).not.toContain("123456");
  });

  it("rejects SSRF OAST evidence and the command allowlist secure control", async () => {
    await using artifacts = new ProofArtifactStore();
    const verification: VerificationEngine = new DefaultVerificationEngine(
      vulnerableAppProfile,
      artifacts,
    );
    const commandFinding = commandInjectionFinding("LEVEL_1", "vulnerableapp-command-level-1");
    const oastClaim: Finding = {
      ...commandFinding,
      proof: {
        type: "oast-callback",
        policyId: "vulnerableapp-command-level-1",
        probeId: "generic-oast",
        token: "callback-token",
        requestIndex: 0,
        callbackUrl: "http://127.0.0.1/callback-token",
        challenge: { location: "query", parameter: "ipaddress", template: "{{challenge}}" },
      },
    };
    const oastResult = verification.preflight(oastClaim, {
      observations: injectionObservations(oastClaim, [{ content: "callback sent" }]),
    });
    expect(oastResult.proof.classification).toBe("server-side-request-forgery");
    expect(oastResult.proof.checks[0]).toMatchObject({
      passed: false,
      description: expect.stringContaining("compatible with"),
    });

    const secureFinding = commandInjectionFinding(
      "LEVEL_6",
      "vulnerableapp-command-level-6-secure-control",
    );
    expect(
      verification.preflight(secureFinding, {
        observations: injectionObservations(secureFinding, [{ content: "" }]),
      }).accepted,
    ).toBe(false);
  });
});
