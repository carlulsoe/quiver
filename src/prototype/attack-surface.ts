import type { Browser } from "playwright-core";
import { mapBrowserContext } from "./attack-surface-context.ts";
import { addOpenApi, buildAttackSurfaceResult } from "./attack-surface-evidence.ts";
import { findBrowserExecutable, launchChromium } from "./attack-surface-scope.ts";
import { createAttackSurfaceState, type AttackSurfaceState } from "./attack-surface-state.ts";
import type {
  AttackSurfaceMap,
  BrowserAttackSurfaceMapperOptions,
} from "./attack-surface-types.ts";

export { discoverGraphqlOperations } from "./discovery/graphql.ts";
export {
  extractOpenApiRequestBodies,
  normalizeAttackSurfaceOrigins,
  resolveEffectiveOpenApiPrefixes,
  resolveOpenApiPrefixes,
} from "./discovery/openapi.ts";
export type {
  AttackSurfaceScope,
  AttackSurfaceOrigin,
  AttackSurfaceDocument,
  AttackSurfaceCallSite,
  AttackSurfaceIdentifierSource,
  AttackSurfaceRequestBody,
  AttackSurfaceGraphqlOperation,
  AttackSurfaceForm,
  AttackSurfaceWebSocket,
  AttackSurfaceRouteDetail,
  AttackSurfaceMap,
  BrowserRequestDecision,
  BrowserRequestMetadata,
  BrowserCookie,
  BrowserAttackSurfaceMapperOptions,
} from "./attack-surface-types.ts";
export { findBrowserExecutable, launchChromium } from "./attack-surface-scope.ts";

/** Maps browser-observed workflows and supplied API descriptions without testing findings. */
export class BrowserAttackSurfaceMapper {
  readonly #state: AttackSurfaceState;

  constructor(options: BrowserAttackSurfaceMapperOptions) {
    this.#state = createAttackSurfaceState(options);
  }

  async map(): Promise<AttackSurfaceMap> {
    const { options } = this.#state;
    addOpenApi(this.#state, options.openApi);
    const executablePath = await findBrowserExecutable(options.executablePath);
    const browser = await (options.launch ?? launchChromium)(executablePath);
    await this.#mapBrowser(browser);
    return buildAttackSurfaceResult(this.#state);
  }

  async #mapBrowser(browser: Browser): Promise<void> {
    try {
      const context = await browser.newContext({
        extraHTTPHeaders: this.#state.options.authenticationHeaders,
        serviceWorkers: "block",
      });
      await mapBrowserContext(this.#state, context);
    } finally {
      for (const lease of this.#state.requestLeases.values()) lease.fail();
      this.#state.requestLeases.clear();
      await browser.close();
    }
  }
}
