import { createHash } from "node:crypto";
import type { SecurityEvalProfileId } from "./security-eval.ts";

export interface EvalMatrixCase {
  index: number;
  profileId: SecurityEvalProfileId;
  heldOutSeed?: string;
}

export function buildEvalMatrix(options: {
  profileIds: readonly SecurityEvalProfileId[];
  trialCount: number;
  runSeed: string;
}): EvalMatrixCase[] {
  if (!Number.isInteger(options.trialCount) || options.trialCount < 1) {
    throw new Error("trialCount must be a positive integer");
  }
  if (!options.runSeed) throw new Error("runSeed must not be empty");
  return Array.from({ length: options.trialCount }, (_, offset) => offset + 1).flatMap((index) =>
    options.profileIds.map((profileId) => ({
      index,
      profileId,
      ...(profileId === "held-out"
        ? { heldOutSeed: deriveHeldOutSeed(options.runSeed, index) }
        : {}),
    })),
  );
}

export function deriveHeldOutSeed(runSeed: string, trialIndex: number): string {
  if (!runSeed) throw new Error("runSeed must not be empty");
  if (!Number.isInteger(trialIndex) || trialIndex < 1) {
    throw new Error("trialIndex must be a positive integer");
  }
  const digest = createHash("sha256")
    .update(`quiver-held-out-v1\0${runSeed}\0${trialIndex}`)
    .digest("hex");
  return `eval-${digest.slice(0, 24)}`;
}
