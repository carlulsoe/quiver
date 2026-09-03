import type { ESTree } from "@oxlint/plugins";
import {
  TRANSPARENT_WRAPPERS,
  aliasSubstitution,
  isBuiltIn,
  isEffectivelyEmptyInterface,
  isEffectivelyEmptyTypeLiteral,
  isUnappliedReferenceTo,
  typeReferenceName,
  unwrapTransparentType,
  type ResolvedType,
  type TypeAliasEnvironment,
  type TypeEnvironment,
  type UnsafeDictionary,
} from "./dictionary-environment.ts";

function unsafeDirectValue(
  type: ESTree.TSType,
  environment: TypeEnvironment,
  substitutions: TypeAliasEnvironment,
  resolvingAliases: ReadonlySet<string>,
): UnsafeDictionary["unsafeValue"] | null {
  const unwrapped = unwrapTransparentType(type);
  if (unwrapped.type === "TSUnknownKeyword") return "unknown";
  if (unwrapped.type === "TSAnyKeyword") return "any";
  if (unwrapped.type === "TSObjectKeyword") return "object";
  if (unwrapped.type === "TSTypeLiteral" && isEffectivelyEmptyTypeLiteral(unwrapped))
    return "empty-object";
  if (unwrapped.type === "TSUnionType") {
    return unwrapped.types.some(
      (member) => unsafeDirectValue(member, environment, substitutions, resolvingAliases) !== null,
    )
      ? "union"
      : null;
  }
  if (unwrapped.type === "TSIntersectionType") {
    const unsafeMembers = unwrapped.types.map((member) =>
      unsafeDirectValue(member, environment, substitutions, resolvingAliases),
    );
    if (unsafeMembers.includes("any")) return "any";
    const firstUnsafeMember = unsafeMembers[0];
    return firstUnsafeMember !== undefined && unsafeMembers.every((member) => member !== null)
      ? firstUnsafeMember
      : null;
  }
  if (unwrapped.type !== "TSTypeReference") return null;
  const name = typeReferenceName(unwrapped);
  if (name === null) return null;
  if (TRANSPARENT_WRAPPERS.has(name) && isBuiltIn(name, environment)) {
    const wrapped = unwrapped.typeArguments?.params[0];
    return wrapped === undefined
      ? null
      : unsafeDirectValue(wrapped, environment, substitutions, resolvingAliases);
  }
  const substitution = substitutions.get(name);
  if (substitution !== undefined) {
    return isUnappliedReferenceTo(substitution, name)
      ? null
      : unsafeDirectValue(substitution, environment, substitutions, resolvingAliases);
  }
  const interfaceDeclarations = environment.interfaces.get(name);
  if (interfaceDeclarations !== undefined) {
    return isEffectivelyEmptyInterface(interfaceDeclarations) ? "empty-object" : null;
  }
  const alias = environment.aliases.get(name);
  if (alias === undefined || resolvingAliases.has(name)) return null;
  const nextSubstitutions = aliasSubstitution(alias, unwrapped, substitutions);
  if (nextSubstitutions === null) return null;
  const nextResolving = new Set(resolvingAliases);
  nextResolving.add(name);
  return unsafeDirectValue(alias.typeAnnotation, environment, nextSubstitutions, nextResolving);
}

export function dictionaryValueTypes(
  type: ESTree.TSType,
  environment: TypeEnvironment,
  substitutions: TypeAliasEnvironment,
  resolvingAliases: ReadonlySet<string>,
): readonly ResolvedType[] {
  const unwrapped = unwrapTransparentType(type);

  if (unwrapped.type === "TSTypeLiteral") {
    return unwrapped.members.flatMap((member): readonly ResolvedType[] =>
      member.type === "TSIndexSignature" && member.typeAnnotation !== null
        ? [{ type: member.typeAnnotation.typeAnnotation, substitutions }]
        : [],
    );
  }

  if (unwrapped.type === "TSMappedType") {
    return unwrapped.typeAnnotation === null
      ? []
      : [{ type: unwrapped.typeAnnotation, substitutions }];
  }

  if (unwrapped.type !== "TSTypeReference") return [];
  const name = typeReferenceName(unwrapped);
  if (name === null) return [];

  const substitution = substitutions.get(name);
  if (substitution !== undefined) {
    return isUnappliedReferenceTo(substitution, name)
      ? []
      : dictionaryValueTypes(substitution, environment, substitutions, resolvingAliases);
  }

  if (TRANSPARENT_WRAPPERS.has(name) && isBuiltIn(name, environment)) {
    const wrapped = unwrapped.typeArguments?.params[0];
    return wrapped === undefined
      ? []
      : dictionaryValueTypes(wrapped, environment, substitutions, resolvingAliases);
  }

  if (name === "Record" && isBuiltIn(name, environment)) {
    const value = unwrapped.typeArguments?.params[1] ?? null;
    return value === null ? [] : [{ type: value, substitutions }];
  }

  if ((name === "Pick" || name === "Omit") && isBuiltIn(name, environment)) {
    const source = unwrapped.typeArguments?.params[0];
    return source === undefined
      ? []
      : dictionaryValueTypes(source, environment, substitutions, resolvingAliases);
  }

  const alias = environment.aliases.get(name);
  if (alias === undefined || resolvingAliases.has(name)) return [];
  const nextSubstitutions = aliasSubstitution(alias, unwrapped, substitutions);
  if (nextSubstitutions === null) return [];
  const nextResolving = new Set(resolvingAliases);
  nextResolving.add(name);
  return dictionaryValueTypes(alias.typeAnnotation, environment, nextSubstitutions, nextResolving);
}

export function classifyUnsafeDictionaryValue(
  valueType: ESTree.TSType,
  environment: TypeEnvironment,
): UnsafeDictionary | null {
  const unsafeValue = unsafeDirectValue(valueType, environment, new Map(), new Set());
  return unsafeValue === null ? null : { kind: "unsafe-dictionary", unsafeValue };
}

export function classifyUnsafeDictionary(
  type: ESTree.TSType,
  environment: TypeEnvironment,
): UnsafeDictionary | null {
  for (const valueType of dictionaryValueTypes(type, environment, new Map(), new Set())) {
    const unsafeValue = unsafeDirectValue(
      valueType.type,
      environment,
      valueType.substitutions,
      new Set(),
    );
    if (unsafeValue !== null) return { kind: "unsafe-dictionary", unsafeValue };
  }
  return null;
}
