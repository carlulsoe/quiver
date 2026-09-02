import {
  authenticationBypassHandler,
  crossPrincipalAccessHandler,
} from "./proof-handlers-access.ts";
import { browserVisibleEffectHandler, oastCallbackHandler } from "./proof-handlers-browser.ts";
import {
  crossPrincipalDataExposureHandler,
  internalFieldExposureHandler,
  responseDifferentialHandler,
  timingDifferentialHandler,
  unauthenticatedSuccessHandler,
} from "./proof-handlers-data.ts";
import {
  commandExecutionChallengeHandler,
  sqlSemanticDifferentialHandler,
} from "./proof-handlers-injection.ts";
import {
  canaryRetrievalHandler,
  fileContentRetrievalHandler,
  redirectDestinationHandler,
} from "./proof-handlers-retrieval.ts";
import { rolePrivilegeDifferentialHandler } from "./proof-handlers-role.ts";
import { browserStateTransitionHandler, stateTransitionHandler } from "./proof-handlers-state.ts";
import type { ProofCheckHandlers } from "./proof-types.ts";

export const proofCheckHandlers: ProofCheckHandlers = {
  "cross-principal-access": crossPrincipalAccessHandler,
  "authentication-bypass": authenticationBypassHandler,
  "role-privilege-differential": rolePrivilegeDifferentialHandler,
  "unauthenticated-success": unauthenticatedSuccessHandler,
  "cross-principal-data-exposure": crossPrincipalDataExposureHandler,
  "internal-field-exposure": internalFieldExposureHandler,
  "response-differential": responseDifferentialHandler,
  "timing-differential": timingDifferentialHandler,
  "sql-semantic-differential": sqlSemanticDifferentialHandler,
  "command-execution-challenge": commandExecutionChallengeHandler,
  "canary-retrieval": canaryRetrievalHandler,
  "file-content-retrieval": fileContentRetrievalHandler,
  "redirect-destination": redirectDestinationHandler,
  "state-transition": stateTransitionHandler,
  "browser-state-transition": browserStateTransitionHandler,
  "browser-visible-effect": browserVisibleEffectHandler,
  "oast-callback": oastCallbackHandler,
};
