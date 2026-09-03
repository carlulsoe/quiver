import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ruleNames = [
  "no-chained-type-assertions",
  "no-conditional-empty-object-spread",
  "no-known-value-widening",
  "no-object-parameters",
  "no-runtime-typeof",
  "no-shape-in-symbol-names",
  "no-unknown-parameters",
  "no-unknown-type-aliases",
  "no-unsafe-dictionary-type",
  "no-widen-then-assert",
] as const;

const repositoryRoot = resolve(import.meta.dir, "../../../..");
const fixtureRoot = import.meta.dir;
const temporaryRoot = await mkdtemp(join(tmpdir(), "quiver-anti-slop-"));
const decoder = new TextDecoder();

try {
  for (const ruleName of ruleNames) {
    const ruleId = `anti-slop/${ruleName}`;
    const configPath = join(temporaryRoot, `${ruleName}.json`);
    await writeFile(
      configPath,
      JSON.stringify({
        jsPlugins: [
          { name: "anti-slop", specifier: join(repositoryRoot, "tools/oxlint/anti-slop/index.ts") },
        ],
        rules: { [ruleId]: "error" },
      }),
    );

    for (const expectation of ["valid", "invalid"] as const) {
      const sourcePath = join(fixtureRoot, expectation, `${ruleName}.ts.txt`);
      const temporaryPath = join(temporaryRoot, `${expectation}-${ruleName}.ts`);
      await writeFile(temporaryPath, await Bun.file(sourcePath).text());

      const result = Bun.spawnSync([
        join(repositoryRoot, "node_modules/.bin/oxlint"),
        "--config",
        configPath,
        "--allow=all",
        "--format=json",
        temporaryPath,
      ]);
      const output = decoder.decode(result.stdout) + decoder.decode(result.stderr);
      const expectedExitCode = expectation === "valid" ? 0 : 1;
      const hasExpectedDiagnostic = output.includes(`anti-slop(${ruleName})`);

      if (result.exitCode !== expectedExitCode) {
        throw new Error(
          `${expectation} fixture for ${ruleId} exited ${result.exitCode}; expected ${expectedExitCode}\n${output}`,
        );
      }
      if (hasExpectedDiagnostic !== (expectation === "invalid")) {
        throw new Error(
          `${expectation} fixture for ${ruleId} produced unexpected output\n${output}`,
        );
      }
    }
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

console.log(`Verified valid and invalid fixtures for ${ruleNames.length} anti-slop rules.`);
