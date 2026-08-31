import type { TargetProfile } from "../prototype/target-profile.ts";

export const heldOutProfile: TargetProfile = {
  id: "held-out",
  displayName: "Quiver randomized held-out target",
  objective:
    "Find the seeded read-only vulnerability while distinguishing it from authorization controls. Routes and identifiers change with each target seed. Treat returned QUIVER-CANARY values as concrete impact evidence and include them in deterministic proof pointers.",
  authenticate: async (target) => {
    target.setAuthentication({ authorization: "Bearer quiver-showcase-user" });
    return { authContext: "held-out-ordinary-user" };
  },
  reproductionAuthentication: {
    description:
      "The local held-out fixture uses a fixed synthetic bearer token; it is not a real credential.",
    commands: [`export QUIVER_TOKEN='quiver-showcase-user'`],
  },
};
