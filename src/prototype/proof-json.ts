import * as v from "valibot";
import { redactCredentialPathValue } from "./security/redaction.ts";
import type { ProofCheck, ValidationObservation } from "./state.ts";

type ProofValue = ProofCheck["actual"];

interface PointerSelection {
  found: boolean;
  value?: ProofValue;
}

const jsonObjectSchema = v.record(v.string(), v.unknown());
const scalarSchema = v.union([v.string(), v.number(), v.boolean()]);
const stringSchema = v.string();

export function canonicalJson(value: ProofValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const object = v.safeParse(jsonObjectSchema, value);
  if (object.success) {
    return `{${Object.entries(object.output)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? String(value);
}

export function pointerChecks(
  observation: ValidationObservation | undefined,
  pointers: readonly string[],
): ProofCheck[] {
  return pointers.map((pointer) => {
    const selected = observation ? jsonPointer(observation.body, pointer) : { found: false };
    return check(
      selected.found,
      `response contains ${pointer}`,
      selectedEvidence(pointer, selected.value),
    );
  });
}

export function differentialPointerChecks(
  control: ValidationObservation | undefined,
  probe: ValidationObservation | undefined,
  pointers: readonly string[],
  controlLabel: string,
  probeLabel: string,
): ProofCheck[] {
  return [
    check(pointers.length > 0, "at least one differential evidence field was declared"),
    ...pointers.flatMap((pointer) => {
      const controlValue = control ? jsonPointer(control.body, pointer) : { found: false };
      const probeValue = probe ? jsonPointer(probe.body, pointer) : { found: false };
      return [
        check(
          controlValue.found && isScalar(controlValue.value),
          `${controlLabel} contains scalar ${pointer}`,
          selectedEvidence(pointer, controlValue.value),
        ),
        check(
          probeValue.found && isScalar(probeValue.value),
          `${probeLabel} contains scalar ${pointer}`,
          selectedEvidence(pointer, probeValue.value),
        ),
        check(
          controlValue.found &&
            probeValue.found &&
            isScalar(controlValue.value) &&
            sameValue(controlValue.value, probeValue.value),
          `${controlLabel} and ${probeLabel} match at ${pointer}`,
          controlValue.found && probeValue.found
            ? `${String(selectedEvidence(pointer, controlValue.value))} == ${String(selectedEvidence(pointer, probeValue.value))}`
            : undefined,
        ),
      ];
    }),
  ];
}

export function selectedValue(
  observations: readonly ValidationObservation[],
  selector: { requestIndex: number; jsonPointer: string },
): PointerSelection {
  const observation = observations[selector.requestIndex];
  return observation ? jsonPointer(observation.body, selector.jsonPointer) : { found: false };
}

export function selectedEvidence(pointer: string, value: ProofValue): ProofValue {
  if (value === undefined) return undefined;
  return redactCredentialPathValue(pointer, value);
}

export function jsonPointer(value: ProofValue, pointer: string): PointerSelection {
  if (pointer === "") return { found: true, value };
  if (!pointer.startsWith("/")) return { found: false };
  let current = value;
  for (const encodedToken of pointer.slice(1).split("/")) {
    const token = encodedToken.replaceAll("~1", "/").replaceAll("~0", "~");
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9]\d*)$/.test(token)) return { found: false };
      const index = Number(token);
      if (index >= current.length) return { found: false };
      current = current[index];
      continue;
    }
    const object = v.safeParse(jsonObjectSchema, current);
    if (!object.success || !Object.hasOwn(object.output, token)) return { found: false };
    current = object.output[token];
  }
  return { found: true, value: current };
}

export function check(passed: boolean, description: string, actual?: ProofValue): ProofCheck {
  const result: ProofCheck = { description, passed };
  if (actual !== undefined) result.actual = actual;
  return result;
}

export function isScalar(value: ProofValue): boolean {
  return v.safeParse(scalarSchema, value).success;
}

export function stringValue(value: ProofValue): string | undefined {
  const parsed = v.safeParse(stringSchema, value);
  return parsed.success ? parsed.output : undefined;
}

export function sameValue(left: ProofValue, right: ProofValue): boolean {
  return left === right;
}

export function isSuccess(status: number): boolean {
  return status >= 200 && status < 300;
}
