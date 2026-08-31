import { readFile } from "node:fs/promises";
import { parse as parseYaml } from "yaml";

export async function loadOpenApi(path: string): Promise<unknown> {
  const source = await readSuppliedFile(path, "OpenAPI");
  let document: unknown;
  try {
    document = parseYaml(source);
  } catch (error) {
    throw new Error(`Could not parse OpenAPI file ${path}: ${String(error)}`);
  }
  if (
    !document ||
    typeof document !== "object" ||
    !("paths" in document) ||
    !(document as { paths?: unknown }).paths ||
    typeof (document as { paths?: unknown }).paths !== "object" ||
    Array.isArray((document as { paths?: unknown }).paths)
  ) {
    throw new Error(`OpenAPI file ${path} must contain a paths object`);
  }
  return document;
}

export async function loadContext(path: string): Promise<string> {
  const context = (await readSuppliedFile(path, "context")).trim();
  if (!context) throw new Error(`Context file ${path} is empty`);
  return context;
}

async function readSuppliedFile(path: string, kind: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    throw new Error(`Could not read ${kind} file ${path}: ${String(error)}`);
  }
}
