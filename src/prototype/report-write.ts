import { mkdir } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";
import type { RunReport } from "./report-create.ts";
import { renderMarkdownReport } from "./report-markdown.ts";

export async function writeRunReport(path: string, report: RunReport): Promise<string> {
  const absolutePath = resolve(path);
  await mkdir(dirname(absolutePath), { recursive: true });
  const contents =
    extname(absolutePath).toLowerCase() === ".md"
      ? renderMarkdownReport(report)
      : `${JSON.stringify(report, null, 2)}\n`;
  await Bun.write(absolutePath, contents);
  return absolutePath;
}
