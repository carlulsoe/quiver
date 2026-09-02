import type { AttackSurfaceMap } from "./attack-surface.ts";
import {
  commitBrowserRequest,
  decideBrowserRequest,
  operationKey,
} from "./scoped-target-policy.ts";
import type { ScopedTargetState } from "./scoped-target-state.ts";

export function mapAttackSurface(
  state: ScopedTargetState,
  options: { maxDocuments?: number } = {},
): Promise<AttackSurfaceMap> {
  state.attackSurfaceResult ??= performAttackSurfaceMap(state, options.maxDocuments ?? 8);
  return state.attackSurfaceResult;
}

async function performAttackSurfaceMap(
  state: ScopedTargetState,
  maxDocuments: number,
): Promise<AttackSurfaceMap> {
  const browserState = await state.sessions.browserState(state.browserActorId);
  const map = await state.attackSurfaceMapper({
    origin: state.origin,
    startPath: state.startPath,
    maxDocuments,
    timeoutMs: state.timeoutMs,
    authenticationHeaders: browserState.headers,
    localStorage: browserState.localStorage,
    sessionStorage: browserState.sessionStorage,
    cookies: browserState.cookies,
    openApi: state.openApi,
    origins: state.attackSurfaceOrigins,
    executablePath: state.browserExecutablePath,
    acquireRequest: state.runtimeSafety ? () => state.runtimeSafety!.acquire() : undefined,
    commitRequest: state.runtimeSafety
      ? (method, path, metadata) =>
          commitBrowserRequest(
            state,
            method,
            metadata?.origin && metadata.origin !== state.origin
              ? `${metadata.origin}${path}`
              : path,
            metadata?.budgeted ?? true,
          )
      : undefined,
    decideRequest: (method, path, metadata) =>
      decideBrowserRequest(
        state,
        method,
        path,
        metadata?.budgeted ?? true,
        metadata?.automaticInteraction ?? false,
        metadata?.scope,
        metadata?.origin,
        metadata?.passiveVisitOnly,
      ),
    onOperationDiscovered: (method, path, source, metadata) => {
      if (
        (metadata?.scope !== undefined && metadata.scope !== "attackable") ||
        metadata?.allowed === false ||
        (source === "browser" && metadata?.automaticInteraction)
      )
        return;
      const targetPath =
        metadata?.origin && metadata.origin !== state.origin ? `${metadata.origin}${path}` : path;
      const key = operationKey(method, targetPath);
      state.mappedOperations.add(key);
      if (source === "openapi") state.browserAllowedOperations.add(key);
    },
  });
  return map;
}
