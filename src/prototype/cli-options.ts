export interface CliOptions {
  target: URL;
  reportPath?: string;
  quiet: boolean;
  help: boolean;
}

export function parseCliOptions(args: string[]): CliOptions {
  let target = new URL("http://127.0.0.1:8888");
  let reportPath: string | undefined;
  let quiet = false;
  let help = false;
  let targetProvided = false;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    if (argument === "--report") {
      reportPath = args[index + 1];
      if (!reportPath || reportPath.startsWith("-")) {
        throw new Error("--report requires a file path");
      }
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

  return { target, reportPath, quiet, help };
}

export const CLI_HELP = `Usage: bun run prototype -- [target] [options]

Options:
  --report <path>  Write a structured JSON run report
  --quiet          Suppress live state rendering
  -h, --help       Show this help
`;
