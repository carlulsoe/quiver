#!/usr/bin/env bun
import { render } from "./render.ts";
import { runPrototype } from "./runner.ts";

const run = await runPrototype({
  target: new URL(process.argv[2] ?? "http://127.0.0.1:8888"),
  onState: render,
});

if (run.state.phase === "failed") process.exitCode = 1;
else if (run.state.validation?.status !== "confirmed") process.exitCode = 2;
