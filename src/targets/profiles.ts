import type { TargetProfile } from "../prototype/target-profile.ts";
import { crapiProfile } from "./crapi.ts";
import { heldOutProfile } from "./held-out.ts";

export const targetProfiles = {
  crapi: crapiProfile,
  "held-out": heldOutProfile,
} satisfies Record<string, TargetProfile>;

export type TargetProfileId = keyof typeof targetProfiles;

export function getTargetProfile(id: TargetProfileId): TargetProfile {
  return targetProfiles[id];
}
