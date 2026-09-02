import { endpointMatchesRequest } from "./endpoint.ts";
import type { ActorId } from "./sessions.ts";
import type { Finding } from "./state.ts";
import type { ProtectedOperationManifest, TargetIdentityManifest } from "./target-manifest.ts";
import type { ProofPolicy } from "./target-profile.ts";
import type { ProofRequest } from "./proof-request-comparison.ts";

export function affectedOperationIsRepresented(
  finding: Pick<Finding, "endpoint" | "method" | "proof" | "reproduction">,
  policies: readonly ProofPolicy[] | undefined,
): boolean {
  if (finding.proof.type === "browser-state-transition") {
    const proof = finding.proof;
    return (
      policies?.some(
        (policy) =>
          policy.kind === "browser-state-transition" &&
          policy.id === proof.policyId &&
          endpointMatchesRequest(finding.endpoint, policy.endpoint) &&
          policy.method === finding.method,
      ) === true
    );
  }
  return finding.reproduction.some(
    ({ path, method }) =>
      endpointMatchesRequest(finding.endpoint, path) &&
      (method ?? "GET") === (finding.method ?? "GET"),
  );
}

export function affectedOperationMatches(
  finding: Pick<Finding, "endpoint" | "method">,
  request: Pick<ProofRequest, "path" | "method"> | undefined,
): boolean {
  return (
    request !== undefined &&
    (request.method ?? "GET") === (finding.method ?? "GET") &&
    endpointMatchesRequest(finding.endpoint, request.path)
  );
}

export function protectedOperationFor(
  operations: readonly ProtectedOperationManifest[] | undefined,
  request: Pick<ProofRequest, "path" | "method"> | undefined,
): ProtectedOperationManifest | undefined {
  if (!request) return undefined;
  const matches = (operations ?? []).filter(
    (operation) =>
      operation.method === (request.method ?? "GET") &&
      endpointMatchesRequest(operation.path, request.path),
  );
  const highestSpecificity = Math.max(...matches.map(({ path }) => operationSpecificity(path)));
  const mostSpecific = matches.filter(
    ({ path }) => operationSpecificity(path) === highestSpecificity,
  );
  const [selected] = mostSpecific;
  return selected &&
    mostSpecific.every(({ authorizedActors }) =>
      sameActorSet(authorizedActors, selected.authorizedActors),
    )
    ? selected
    : undefined;
}

export function operationSpecificity(path: string): number {
  return new URL(path, "http://proof.invalid").pathname
    .split("/")
    .filter(
      (segment) =>
        segment.length > 0 &&
        !/^(?:<[^>]+>|\{[^}]+\}|:[A-Za-z_$][\w$]*)$/.test(decodeURIComponent(segment)),
    ).length;
}

export function sameActorSet(left: readonly ActorId[], right: readonly ActorId[]): boolean {
  return left.length === right.length && left.every((actorId) => right.includes(actorId));
}

export function identityFor(
  identities: readonly TargetIdentityManifest[] | undefined,
  actorId: ActorId | undefined,
): TargetIdentityManifest | undefined {
  return identities?.find((identity) => identity.id === actorId);
}

export function roleRank(role: TargetIdentityManifest["role"]): number {
  switch (role) {
    case "anonymous":
      return 0;
    case "user":
      return 1;
    case "administrator":
      return 2;
  }
}
