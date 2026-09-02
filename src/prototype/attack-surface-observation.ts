import type { Request } from "playwright-core";
import {
  discoverGraphqlOperationsFromRequest,
  observeRequestBody,
} from "./discovery/request-evidence.ts";
import type { FormCandidate } from "./discovery/forms.ts";
import { isCredentialHeaderName } from "./security/credentials.ts";
import { mergeEvidence } from "./attack-surface-evidence.ts";
import { scopedUrl } from "./attack-surface-scope.ts";
import type { AttackSurfaceState } from "./attack-surface-state.ts";
import type { AttackSurfaceCallSite, AttackSurfaceScope } from "./attack-surface-types.ts";

export function recordForms(
  state: AttackSurfaceState,
  forms: FormCandidate[],
  documentPath: string,
): void {
  for (const form of forms) {
    if (
      state.forms.some(
        (item) =>
          item.documentPath === documentPath &&
          item.index === form.index &&
          item.action === form.action &&
          item.method === form.method,
      )
    ) {
      continue;
    }
    state.forms.push({
      index: form.index,
      documentPath,
      action: form.action,
      method: form.method,
      intent: form.intent,
      fields: form.fields.map(({ name, type, valueSource }) => ({ name, type, valueSource })),
      fileFields: form.fileFields,
      attempted: false,
      submitted: false,
    });
    if (form.fileFields.length === 0) continue;
    const scoped = scopedUrl(state, form.action);
    if (!scoped) continue;
    mergeEvidence(state, scoped.url, form.method, "form", undefined, {
      body: {
        contentType: form.enctype || "multipart/form-data",
        source: "form",
        fields: form.fields.map(({ name }) => name),
        files: form.fileFields.map((field) => ({ field })),
      },
    });
  }
}

export function observeRequest(
  state: AttackSurfaceState,
  request: Request,
  url: URL,
  scope: AttackSurfaceScope,
  documentPath: string,
  allowed: boolean,
  blockedReason: string | undefined,
): boolean {
  const method = request.method().toUpperCase();
  const resourceType = request.resourceType();
  if (["script", "stylesheet", "image", "font", "media"].includes(resourceType)) return false;
  if (resourceType === "document" && method === "GET") return false;
  const headers = request.headers();
  const authentication =
    headers.authorization ||
    headers.cookie ||
    (url.origin === state.options.origin &&
      Object.keys(state.options.authenticationHeaders ?? {}).some(isCredentialHeaderName))
      ? "likely"
      : "unknown";
  const callSite: AttackSurfaceCallSite = {
    documentPath,
    method,
    authentication,
    allowed,
  };
  if (blockedReason) callSite.blockedReason = blockedReason;
  mergeEvidence(state, url, method, `browser:${resourceType}:${documentPath}`, callSite, {
    examplePath: `${url.pathname}${url.search}`,
    body: observeRequestBody(request),
    graphql: discoverGraphqlOperationsFromRequest(request),
    scope,
  });
  return true;
}
