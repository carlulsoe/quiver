export { createTypeEnvironment } from "./dictionary-environment.ts";
export type {
  TypeEnvironment,
  UnsafeDictionary,
  WideningTarget,
  WideningTargetKind,
} from "./dictionary-environment.ts";
export { classifyUnsafeDictionary, classifyUnsafeDictionaryValue } from "./dictionary-unsafe.ts";
export {
  classifyWideningTarget,
  isKnownEvidenceExpression,
  isPopulatedObjectExpression,
} from "./dictionary-widening.ts";
