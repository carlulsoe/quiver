import type { LedgerRequest } from "./campaign-ledger.ts";

export function ledgerRequestKey(
  request: Pick<LedgerRequest, "path" | "method" | "headers" | "body" | "actorId" | "sampleId">,
): string {
  const url = new URL(request.path, "http://scope.invalid");
  url.searchParams.sort();
  const headers = Object.entries(request.headers ?? {})
    .map(([name, value]) => [name.toLowerCase(), value] as const)
    .sort(([left], [right]) => left.localeCompare(right));
  return JSON.stringify([
    request.method ?? "GET",
    request.actorId,
    `${url.pathname}${url.search}`,
    headers,
    request.body ?? "",
    request.sampleId ?? "",
  ]);
}
