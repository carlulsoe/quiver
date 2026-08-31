import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { loadContext, loadOpenApi } from "./campaign-input.ts";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true })));
});

describe("supplied campaign input", () => {
  it("loads YAML OpenAPI and text context", async () => {
    const directory = await mkdtemp(join(tmpdir(), "quiver-input-"));
    directories.push(directory);
    const openApiPath = join(directory, "api.yaml");
    const contextPath = join(directory, "context.md");
    await Promise.all([
      writeFile(
        openApiPath,
        "openapi: 3.1.0\npaths:\n  /orders/{id}:\n    get:\n      summary: Read order\n",
      ),
      writeFile(contextPath, "  Test tenant is isolated from tenant B.  \n"),
    ]);

    await expect(loadOpenApi(openApiPath)).resolves.toMatchObject({
      paths: { "/orders/{id}": { get: { summary: "Read order" } } },
    });
    await expect(loadContext(contextPath)).resolves.toBe("Test tenant is isolated from tenant B.");
  });

  it("rejects an OpenAPI document without paths", async () => {
    const directory = await mkdtemp(join(tmpdir(), "quiver-input-"));
    directories.push(directory);
    const path = join(directory, "api.yaml");
    await writeFile(path, "openapi: 3.1.0\n");

    await expect(loadOpenApi(path)).rejects.toThrow("must contain a paths object");
  });
});
