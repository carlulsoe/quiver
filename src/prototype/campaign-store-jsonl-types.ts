import type { DurableAppend } from "./campaign-store-log.ts";

export interface CampaignStoreStatistics {
  durableWrites: number;
  records: number;
  actionRecords: number;
  checkpointRecords: number;
  fullStateRecords: number;
  bytes: number;
}

export interface JsonlCampaignStoreOptions {
  checkpointActionInterval?: number;
  durableAppend?: DurableAppend;
}
