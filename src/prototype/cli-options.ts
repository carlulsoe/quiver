import type { TargetProfileId } from "../targets/profiles.ts";

export interface CliOptions {
  target: URL;
  profileId: TargetProfileId;
  reportPath?: string;
  quiet: boolean;
  help: boolean;
  requestBudget: number;
  openApiPath?: string;
  contextPath?: string;
}

export function parseCliOptions(args: string[]): CliOptions {
  let target: URL | undefined;
  let profileId: TargetProfileId = "crapi";
  let reportPath: string | undefined;
  let quiet = false;
  let help = false;
  let targetProvided = false;
  let requestBudget = 30;
  let openApiPath: string | undefined;
  let contextPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    if (argument === "--report") {
      reportPath = args[index + 1];
      if (!reportPath || reportPath.startsWith("-")) {
        throw new Error("--report requires a file path");
      }
      index += 1;
    } else if (argument === "--openapi") {
      openApiPath = requiredPath(args[index + 1], "--openapi");
      index += 1;
    } else if (argument === "--context") {
      contextPath = requiredPath(args[index + 1], "--context");
      index += 1;
    } else if (argument === "--profile") {
      const value = args[index + 1];
      if (value !== "crapi" && value !== "held-out") {
        throw new Error("--profile must be one of: crapi, held-out");
      }
      profileId = value;
      index += 1;
    } else if (argument === "--budget") {
      const value = Number(args[index + 1]);
      if (!Number.isInteger(value) || value < 3) {
        throw new Error("--budget must be an integer of at least 3");
      }
      requestBudget = value;
      index += 1;
    } else if (argument === "--quiet") {
      quiet = true;
    } else if (argument === "--help" || argument === "-h") {
      help = true;
    } else if (argument.startsWith("-")) {
      throw new Error(`Unknown option: ${argument}`);
    } else {
      if (targetProvided) throw new Error("Only one target URL is allowed");
      target = new URL(argument);
      targetProvided = true;
    }
  }

  target ??= new URL(profileId === "held-out" ? "http://127.0.0.1:8899" : "http://127.0.0.1:8888");
  return {
    target,
    profileId,
    reportPath,
    quiet,
    help,
    requestBudget,
    ...(openApiPath ? { openApiPath } : {}),
    ...(contextPath ? { contextPath } : {}),
  };
}

function requiredPath(value: string | undefined, option: string): string {
  if (!value || value.startsWith("-")) throw new Error(`${option} requires a file path`);
  return value;
}

export const CLI_HELP = `Usage: bun run campaign -- [target] [options]

Options:
  --report <path>  Write a .json trace or polished .md report
  --profile <id>   Target profile: crapi or held-out (default: crapi)
  --budget <count> Total HTTP request budget (default: 30)
  --openapi <path> Merge a supplied OpenAPI JSON or YAML document
  --context <path> Supply target notes and assessment context to explorers
  --quiet          Suppress live state rendering
  -h, --help       Show this help
`;
