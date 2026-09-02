import { CoordinatorBehavior } from "./adaptive-coordinator-behavior.ts";

export * from "./adaptive-coordinator-types.ts";

/** Persistent campaign decision engine for short-lived workers. */
export class PersistentCoordinator extends CoordinatorBehavior {}

/** @deprecated Use PersistentCoordinator. */
export { PersistentCoordinator as AdaptiveCoordinator };
