import type { TargetProfile } from "../prototype/target-profile.ts";
import { brokenCrystalsProfile } from "./broken-crystals.ts";
import { crapiProfile } from "./crapi.ts";
import { heldOutProfile } from "./held-out.ts";
import { vampiSecureProfile, vampiVulnerableProfile } from "./vampi.ts";
import { vulnerableAppProfile } from "./vulnerableapp.ts";

export const targetProfiles = {
  "broken-crystals": brokenCrystalsProfile,
  crapi: crapiProfile,
  "held-out": heldOutProfile,
  "vampi-secure": vampiSecureProfile,
  "vampi-vulnerable": vampiVulnerableProfile,
  vulnerableapp: vulnerableAppProfile,
} satisfies Record<string, TargetProfile>;

export type TargetProfileId = keyof typeof targetProfiles;

export function getTargetProfile(id: TargetProfileId): TargetProfile {
  return targetProfiles[id];
}

const defaultTargets: Record<TargetProfileId, string> = {
  "broken-crystals": "http://127.0.0.1:3000",
  crapi: "http://127.0.0.1:8888",
  "held-out": "http://127.0.0.1:8899",
  "vampi-secure": "http://127.0.0.1:5001/ui/",
  "vampi-vulnerable": "http://127.0.0.1:5002/ui/",
  vulnerableapp: "http://127.0.0.1:9090/VulnerableApp/",
};

export function getDefaultTarget(id: TargetProfileId): URL {
  return new URL(defaultTargets[id]);
}
