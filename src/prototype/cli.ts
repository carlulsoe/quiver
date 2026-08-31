#!/usr/bin/env bun
import { CLI_HELP, parseCliOptions } from "./cli-options.ts";
import { render } from "./render.ts";
import { createRunReport, writeRunReport } from "./report.ts";
import { runCampaign } from "./runner.ts";
import { getTargetProfile } from "../targets/profiles.ts";
import { loadContext, loadOpenApi } from "./campaign-input.ts";

const options = parseCliOptions(process.argv.slice(2));
if (options.help) {
  console.log(CLI_HELP);
} else {
  const [openApi, context] = await Promise.all([
    options.openApiPath ? loadOpenApi(options.openApiPath) : undefined,
    options.contextPath ? loadContext(options.contextPath) : undefined,
  ]);
  const run = await runCampaign({
    target: options.target,
    profile: getTargetProfile(options.profileId),
    requestBudget: options.requestBudget,
    openApi,
    context,
    onState: options.quiet ? undefined : render,
  });

  if (options.reportPath) {
    const reportPath = await writeRunReport(options.reportPath, createRunReport(run));
    console.error(`Run report: ${reportPath}`);
  }

  if (run.state.phase === "failed") process.exitCode = 1;
  else if (!run.state.validations.some((validation) => validation.status === "confirmed"))
    process.exitCode = 2;
}
