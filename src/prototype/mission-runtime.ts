import { shouldFallbackModel, type ModelRoute, type RoutedModel } from "./model-routing.ts";

/** Owns model selection and the no-replay-after-tools fallback invariant for one mission. */
export class RoutedMission {
  #route: ModelRoute;
  #index = 0;

  constructor(route: ModelRoute) {
    this.#route = route;
  }

  get route(): ModelRoute {
    return this.#route;
  }

  get model(): RoutedModel {
    const model = this.#route.candidates[this.#index];
    if (!model) throw new Error("Model route has no current candidate");
    return model;
  }

  reset(route: ModelRoute): void {
    this.#route = route;
    this.#index = 0;
  }

  async run<T>(
    attempt: (model: RoutedModel, markToolInvoked: () => void) => Promise<T>,
    onAttempt?: (model: RoutedModel, attempt: number) => void,
  ): Promise<T> {
    while (true) {
      let toolInvoked = false;
      const model = this.model;
      onAttempt?.(model, this.#index + 1);
      try {
        return await attempt(model, () => {
          toolInvoked = true;
        });
      } catch (error) {
        if (
          !shouldFallbackModel(error, toolInvoked) ||
          this.#index + 1 >= this.#route.candidates.length
        ) {
          throw error;
        }
        this.#index += 1;
      }
    }
  }
}
