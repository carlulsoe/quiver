import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, fsyncSync, mkdirSync, openSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import type { CampaignAction, CampaignState } from "./state.ts";

export interface JsonlBaseRecord {
  version: 1;
  campaignId: string;
  sequence: number;
}
export interface JsonlStateRecord extends JsonlBaseRecord {
  kind: "created" | "checkpoint";
  state: CampaignState;
  checksum: string;
}
export interface JsonlActionRecord extends JsonlBaseRecord {
  kind: "action";
  action: CampaignAction;
}
export type JsonlRecord = JsonlStateRecord | JsonlActionRecord;
export type DurableAppend = (descriptor: number, records: readonly JsonlRecord[]) => number;
export function openDurableLog(path: string): number {
  mkdirSync(dirname(path), { recursive: true });
  return openSync(path, "a", 0o600);
}
export function appendDurably(descriptor: number, records: readonly JsonlRecord[]): number {
  const bytes = serializeJsonlRecords(records);
  writeAll(descriptor, bytes);
  fsyncSync(descriptor);
  return bytes.length;
}
export function serializeJsonlRecords(records: readonly JsonlRecord[]): Buffer {
  return Buffer.from(records.map((record) => JSON.stringify(record)).join("\n") + "\n", "utf8");
}
export function createStateRecord(
  campaignId: string,
  sequence: number,
  kind: JsonlStateRecord["kind"],
  current: CampaignState,
): JsonlStateRecord {
  const state = structuredClone(current);
  return { version: 1, campaignId, sequence, kind, state, checksum: checksumState(state) };
}
export function isCheckpointBoundary(action: CampaignAction): boolean {
  return (
    ["phase", "pause", "resume", "cancel", "halt", "recover", "history-elapsed"] as const
  ).some((type) => type === action.type);
}
function writeAll(descriptor: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(descriptor, bytes, offset, bytes.length - offset, null);
    if (written < 1) throw new Error("Campaign log write made no forward progress");
    offset += written;
  }
}
export function acquireLogLock(path: string): number {
  mkdirSync(dirname(path), { recursive: true });
  const descriptor = openSync(path, "a+", 0o600);
  try {
    const result = spawnSync("flock", ["--exclusive", "--nonblock", "3"], {
      stdio: ["ignore", "ignore", "pipe", descriptor],
      encoding: "utf8",
    });
    if (result.error)
      throw new Error("The durable JSONL store requires the util-linux flock command", {
        cause: result.error,
      });
    if (result.status !== 0)
      throw new Error(`Campaign log is already owned by another process: ${path}`);
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}
export function checksumState(state: CampaignState): string {
  return createHash("sha256").update(JSON.stringify(state)).digest("hex");
}
export function assertStateChecksum(record: JsonlStateRecord): void {
  if (checksumState(record.state) !== record.checksum)
    throw new Error(`Campaign ${record.campaignId} checkpoint checksum mismatch`);
}
export function assertRecord(record: JsonlRecord, line: number): void {
  if (
    !record ||
    record.version !== 1 ||
    !record.campaignId ||
    !Number.isSafeInteger(record.sequence) ||
    record.sequence < 1 ||
    !["created", "action", "checkpoint"].includes(record.kind)
  )
    throw new Error(`Invalid campaign JSONL record on line ${line}`);
}
