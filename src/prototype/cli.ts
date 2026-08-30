#!/usr/bin/env bun
import { CLI_HELP, parseCliOptions } from "./cli-options.ts";
import { render } from "./render.ts";
import { createRunReport, writeRunReport } from "./report.ts";
import { runPrototype } from "./runner.ts";
import { crapiProfile } from "../targets/crapi.ts";

const options = parseCliOptions(process.argv.slice(2));
if (options.help) {
  console.log(CLI_HELP);
} else {
  const run = await runPrototype({
    target: options.target,
    profile: crapiProfile,
    onState: options.quiet ? undefined : render,
  });

  if (options.reportPath) {
    const reportPath = await writeRunReport(options.reportPath, createRunReport(run));
    console.error(`Run report: ${reportPath}`);
  }

  if (run.state.phase === "failed") process.exitCode = 1;
  else if (run.state.validation?.status !== "confirmed") process.exitCode = 2;
}
