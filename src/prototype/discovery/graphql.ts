import type { AttackSurfaceGraphqlOperation } from "../attack-surface.ts";

export function discoverGraphqlOperations(query: string): AttackSurfaceGraphqlOperation[] {
  const tokens = graphqlTokens(query);
  const operations: AttackSurfaceGraphqlOperation[] = [];
  let index = 0;
  while (index < tokens.length) {
    if (tokens[index] === "fragment") {
      while (index < tokens.length && tokens[index] !== "{") index += 1;
      index = tokens[index] === "{" ? skipGroup(tokens, index, "{", "}") : tokens.length;
      continue;
    }
    let type: AttackSurfaceGraphqlOperation["type"] = "query";
    let name: string | undefined;
    if (["query", "mutation", "subscription"].includes(tokens[index] ?? "")) {
      type = tokens[index] as AttackSurfaceGraphqlOperation["type"];
      index += 1;
      if (isGraphqlName(tokens[index]) && tokens[index] !== "on") name = tokens[index++];
      if (tokens[index] === "(") index = skipGroup(tokens, index, "(", ")");
      while (tokens[index] === "@") {
        index += 2;
        if (tokens[index] === "(") index = skipGroup(tokens, index, "(", ")");
      }
      while (index < tokens.length && tokens[index] !== "{") index += 1;
    } else if (tokens[index] !== "{") {
      index += 1;
      continue;
    }
    if (tokens[index] !== "{") break;
    const rootFields: string[] = [];
    let depth = 0;
    for (; index < tokens.length; index += 1) {
      const token = tokens[index]!;
      if (token === "{") {
        depth += 1;
        continue;
      }
      if (token === "}") {
        depth -= 1;
        if (depth === 0) {
          index += 1;
          break;
        }
        continue;
      }
      if (depth === 1 && token === "...") {
        while (index + 1 < tokens.length && !["{", "}"].includes(tokens[index + 1]!)) {
          index += 1;
        }
        continue;
      }
      if (depth !== 1 || !isGraphqlName(token)) continue;
      const aliased = tokens[index + 1] === ":" && isGraphqlName(tokens[index + 2]);
      const field = aliased ? tokens[index + 2]! : token;
      if (!rootFields.includes(field) && !["fragment", "on"].includes(field)) {
        rootFields.push(field);
      }
      let cursor = index + (aliased ? 3 : 1);
      if (tokens[cursor] === "(") cursor = skipGroup(tokens, cursor, "(", ")");
      while (tokens[cursor] === "@") {
        cursor += 2;
        if (tokens[cursor] === "(") cursor = skipGroup(tokens, cursor, "(", ")");
      }
      index = cursor - 1;
    }
    const operation: AttackSurfaceGraphqlOperation = { type, rootFields };
    if (name) operation.name = name;
    operations.push(operation);
  }
  return operations;
}

function graphqlTokens(query: string): string[] {
  const scrubbed = query
    .replace(/#[^\r\n]*/g, " ")
    .replace(/"""[\s\S]*?"""/g, " ")
    .replace(/"(?:\\.|[^"\\])*"/g, " ");
  return scrubbed.match(/\.\.\.|\$?[_A-Za-z][_0-9A-Za-z]*|[{}():@!,]|\[|\]/g) ?? [];
}

function skipGroup(tokens: readonly string[], start: number, open: string, close: string): number {
  let depth = 0;
  for (let index = start; index < tokens.length; index += 1) {
    if (tokens[index] === open) depth += 1;
    if (tokens[index] === close) {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  return tokens.length;
}

function isGraphqlName(value: string | undefined): value is string {
  return value !== undefined && /^[_A-Za-z][_0-9A-Za-z]*$/.test(value);
}
