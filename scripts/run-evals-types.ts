import type { SecurityEvalOutput } from "../src/evals/security-eval.ts";

export interface JsonAssertionResult {
  status: string;
  duration?: number;
  failureMessages: string[];
  meta?: {
    eval?: { output?: SecurityEvalOutput };
    harness?: { run?: { session?: { events?: unknown[] } } };
  };
}
export interface JsonTestReport {
  success: boolean;
  testResults: Array<{ assertionResults: JsonAssertionResult[] }>;
  numTotalTests?: number;
  numPassedTests?: number;
  numFailedTests?: number;
  numPendingTests?: number;
  numTodoTests?: number;
  numTotalTestSuites?: number;
  numPassedTestSuites?: number;
  numFailedTestSuites?: number;
  numPendingTestSuites?: number;
}
export interface ReportEntry {
  report: JsonTestReport;
  assertion: JsonAssertionResult;
}
