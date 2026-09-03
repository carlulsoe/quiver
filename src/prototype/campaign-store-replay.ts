import { existsSync, readFileSync, truncateSync } from "node:fs";
import {
  assertRecord,
  assertStateChecksum,
  checksumState,
  type JsonlRecord,
} from "./campaign-store-log.ts";
import { reduceCampaign, withRuntimeState, type CampaignState } from "./state.ts";

export interface DurableCampaign {
  state: CampaignState;
  sequence: number;
  actionsSinceCheckpoint: number;
}

export function replayCampaignLog(path: string): Map<string, DurableCampaign> {
  const campaigns = new Map<string, DurableCampaign>();
  if (!existsSync(path)) return campaigns;
  const contents = readFileSync(path);
  const completeLength =
    contents.at(-1) === 0x0a ? contents.length : contents.lastIndexOf(0x0a) + 1;
  const complete = contents.subarray(0, completeLength).toString("utf8");
  if (completeLength !== contents.length) truncateSync(path, completeLength);
  for (const [index, line] of complete.split("\n").entries()) {
    if (!line) continue;
    let record: JsonlRecord;
    try {
      record = JSON.parse(line) as JsonlRecord;
    } catch {
      throw new Error(`Invalid campaign JSONL record on line ${index + 1}`);
    }
    assertRecord(record, index + 1);
    replayRecord(campaigns, record);
  }
  return campaigns;
}

function replayRecord(campaigns: Map<string, DurableCampaign>, record: JsonlRecord): void {
  const current = campaigns.get(record.campaignId);
  const expected = (current?.sequence ?? 0) + 1;
  if (record.sequence !== expected) {
    throw new Error(`Campaign ${record.campaignId} sequence ${record.sequence} is not ${expected}`);
  }
  if (record.kind === "created") {
    if (current) throw new Error(`Campaign ${record.campaignId} was created more than once`);
    assertStateChecksum(record);
    campaigns.set(record.campaignId, {
      state: structuredClone(withRuntimeState(record.state)),
      sequence: record.sequence,
      actionsSinceCheckpoint: 0,
    });
    return;
  }
  if (!current) throw new Error(`Campaign ${record.campaignId} has no creation record`);
  if (record.kind === "action") {
    current.state = reduceCampaign(current.state, record.action);
    current.actionsSinceCheckpoint += 1;
  } else {
    assertStateChecksum(record);
    const checkpoint = withRuntimeState(record.state);
    if (checksumState(current.state) !== checksumState(checkpoint)) {
      throw new Error(`Campaign ${record.campaignId} checkpoint does not match its action log`);
    }
    current.state = structuredClone(checkpoint);
    current.actionsSinceCheckpoint = 0;
  }
  current.sequence = record.sequence;
}
