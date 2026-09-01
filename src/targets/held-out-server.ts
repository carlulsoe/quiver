#!/usr/bin/env bun
import { createHeldOutFixture } from "./held-out-fixture.ts";
import { mkdir, rename, writeFile } from "node:fs/promises";

const port = Number.parseInt(process.env.QUIVER_HELD_OUT_PORT ?? "8899", 10);
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error("QUIVER_HELD_OUT_PORT must be a valid port");
}
const seed = process.env.QUIVER_HELD_OUT_SEED ?? crypto.randomUUID();
const fixture = createHeldOutFixture(seed);
const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  fetch: fixture.fetch,
});
await mkdir(".prototype", { recursive: true });
const seedTempPath = `.prototype/held-out-seed.${process.pid}.tmp`;
await writeFile(seedTempPath, `${seed}\n`, { encoding: "utf8", mode: 0o600 });
await rename(seedTempPath, ".prototype/held-out-seed");

console.log(`Quiver held-out target: ${server.url}`);
console.log(`Seed: ${seed}`);
console.log(`Namespace: ${fixture.namespace}`);
console.log("Press Ctrl-C to stop.");
