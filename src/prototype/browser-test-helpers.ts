import type { Browser } from "playwright-core";
import * as v from "valibot";

const browserMethodsSchema = v.object({
  newContext: v.function(),
  close: v.function(),
});

export const browserStubSchema = v.custom<Browser>(
  (input) => v.safeParse(browserMethodsSchema, input).success,
  "Browser stubs must provide newContext and close methods",
);
