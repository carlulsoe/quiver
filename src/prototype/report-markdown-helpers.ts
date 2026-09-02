import { isCredentialHeaderName } from "./security/credentials.ts";
import { actorIds } from "./sessions.ts";
import type { RunReport } from "./report-create.ts";
import type { ReproductionRequest } from "./state.ts";

export function reproductionActorIds(report: RunReport): string[] {
  const used = report.findings.flatMap((finding) => [
    ...finding.reproduction.map(({ actorId }) => actorId),
    ...(finding.validation?.reproduction?.map(({ actorId }) => actorId) ?? []),
    ...(finding.validation?.replayedProof?.type === "browser-visible-effect"
      ? [finding.validation.replayedProof.pageActorId]
      : []),
  ]);
  return [...new Set(used)].filter((actorId) => actorId !== actorIds.anonymous);
}

export function credentialVariables(actorIdsUsed: readonly string[]): Map<string, string> {
  const variables = new Map<string, string>();
  const claimed = new Set<string>();
  for (const actorId of actorIdsUsed) {
    const base = `QUIVER_TOKEN_${actorId.toUpperCase().replaceAll(/[^A-Z0-9]+/g, "_")}`;
    let variable = base;
    let suffix = 2;
    while (claimed.has(variable)) variable = `${base}_${suffix++}`;
    claimed.add(variable);
    variables.set(actorId, variable);
  }
  return variables;
}

export function actorAuthenticationCommands(
  actorIdsUsed: readonly string[],
  variables: ReadonlyMap<string, string>,
  authentication: RunReport["reproductionAuthentication"],
): string[] {
  const fallbackActor = actorIdsUsed.includes(actorIds.ordinary)
    ? actorIds.ordinary
    : actorIdsUsed[0];
  return actorIdsUsed.flatMap((actorId) => {
    const variable = variables.get(actorId)!;
    const configured = authentication?.actors?.[actorId];
    if (configured)
      return [
        `# ${actorId}: ${configured.description}`,
        ...configured.commands,
        `export ${variable}="$QUIVER_TOKEN"`,
      ];
    if (authentication && actorId === fallbackActor)
      return [`# ${actorId}`, ...authentication.commands, `export ${variable}="$QUIVER_TOKEN"`];
    return [`: "\${${variable}:?Set ${variable} for actor ${actorId}}"`];
  });
}

export function curlCommand(
  request: ReproductionRequest,
  report: RunReport,
  variables: ReadonlyMap<string, string>,
): string {
  const url = new URL(request.path, report.target).href;
  const auth =
    request.actorId === actorIds.anonymous
      ? ""
      : ` --header 'Authorization: Bearer '"$${variables.get(request.actorId)}"`;
  const headers = Object.entries(request.headers ?? {})
    .flatMap(([name, value]) => {
      if (!isCredentialHeaderName(name)) return [` --header ${shellQuote(`${name}: ${value}`)}`];
      if (request.actorId !== actorIds.anonymous && name.toLowerCase() === "authorization")
        return [];
      const variable = `QUIVER_HEADER_${name
        .toUpperCase()
        .replaceAll(/[^A-Z0-9]+/g, "_")
        .replaceAll(/^_+|_+$/g, "")}`;
      return [` --header ${shellQuote(`${name}: `)}"$${variable}"`];
    })
    .join("");
  const body =
    request.body === undefined
      ? ""
      : request.body.includes("[REDACTED]") || request.body.includes("%5BREDACTED%5D")
        ? ' --data-raw "$QUIVER_REQUEST_BODY"'
        : ` --data-raw ${shellQuote(request.body)}`;
  return `curl --silent --show-error --request ${request.method ?? "GET"}${auth}${headers}${body} ${shellQuote(url)}`;
}

export function inlineValue<Value>(value: Value): string {
  return (JSON.stringify(value) ?? "").replaceAll("`", "\\`").slice(0, 160);
}
export function escapeTable(value: string): string {
  return value.replaceAll("|", "\\|").replaceAll("\n", " ");
}
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
