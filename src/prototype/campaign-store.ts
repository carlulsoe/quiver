import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  truncateSync,
  writeSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import {
  reduceCampaign,
  withRuntimeState,
  type CampaignAction,
  type CampaignState,
} from "./state.ts";

/** Persistence seam for one active campaign at a time. */
export interface CampaignStore {
  create(campaignId: string, state: CampaignState): CampaignState;
  load(campaignId: string): CampaignState;
  apply(action: CampaignAction): void;
  checkpoint(): CampaignState;
}

/** Current process-local campaign adapter. */
export class InMemoryCampaignStore implements CampaignStore {
  readonly #campaigns = new Map<string, CampaignState>();
  #activeCampaignId?: string;

  constructor(campaigns: Iterable<readonly [string, CampaignState]> = []) {
    for (const [campaignId, state] of campaigns) {
      this.#campaigns.set(campaignId, cloneState(withRuntimeState(state)));
    }
  }

  create(campaignId: string, state: CampaignState): CampaignState {
    assertCampaignId(campaignId);
    if (this.#campaigns.has(campaignId)) throw new Error(`Campaign ${campaignId} already exists`);
    this.#campaigns.set(campaignId, cloneState(withRuntimeState(state)));
    this.#activeCampaignId = campaignId;
    return this.checkpoint();
  }

  load(campaignId: string): CampaignState {
    if (!this.#campaigns.has(campaignId)) throw new Error(`Unknown campaign ${campaignId}`);
    this.#activeCampaignId = campaignId;
    return this.checkpoint();
  }

  apply(action: CampaignAction): void {
    const campaignId = this.#requireActiveCampaign();
    const current = this.#campaigns.get(campaignId)!;
    this.#campaigns.set(campaignId, reduceCampaign(current, action));
  }

  checkpoint(): CampaignState {
    const campaignId = this.#requireActiveCampaign();
    return cloneState(this.#campaigns.get(campaignId)!);
  }

  #requireActiveCampaign(): string {
    if (!this.#activeCampaignId) throw new Error("Load a campaign before using the store");
    return this.#activeCampaignId;
  }
}

interface JsonlBaseRecord {
  version: 1;
  campaignId: string;
  sequence: number;
}

interface JsonlStateRecord extends JsonlBaseRecord {
  kind: "created" | "checkpoint";
  state: CampaignState;
  checksum: string;
}

interface JsonlActionRecord extends JsonlBaseRecord {
  kind: "action";
  action: CampaignAction;
}

type JsonlRecord = JsonlStateRecord | JsonlActionRecord;

interface DurableCampaign {
  state: CampaignState;
  sequence: number;
  dirty: boolean;
}

/**
 * Append-only JSONL adapter. Actions are flushed before they become visible to the caller;
 * checkpoints accelerate replay and are checksum verified. A torn final line is ignored.
 */
export class JsonlCampaignStore implements CampaignStore {
  readonly path: string;
  readonly #lockPath: string;
  readonly #lockDescriptor: number;
  readonly #campaigns = new Map<string, DurableCampaign>();
  #activeCampaignId?: string;
  #closed = false;

  constructor(path: string, campaigns: Iterable<readonly [string, CampaignState]> = []) {
    this.path = resolve(path);
    this.#lockPath = `${this.path}.lock`;
    this.#lockDescriptor = acquireLogLock(this.#lockPath);
    try {
      this.#replay();
      for (const [campaignId, state] of campaigns) {
        if (!this.#campaigns.has(campaignId)) this.create(campaignId, state);
      }
    } catch (error) {
      this.close();
      throw error;
    }
  }

  create(campaignId: string, state: CampaignState): CampaignState {
    this.#assertOpen();
    assertCampaignId(campaignId);
    if (this.#campaigns.has(campaignId)) throw new Error(`Campaign ${campaignId} already exists`);
    const durable: DurableCampaign = {
      state: cloneState(withRuntimeState(state)),
      sequence: 0,
      dirty: false,
    };
    this.#appendState(campaignId, "created", durable);
    this.#campaigns.set(campaignId, durable);
    this.#activeCampaignId = campaignId;
    return cloneState(durable.state);
  }

  load(campaignId: string): CampaignState {
    this.#assertOpen();
    const campaign = this.#campaigns.get(campaignId);
    if (!campaign) throw new Error(`Unknown campaign ${campaignId}`);
    this.#activeCampaignId = campaignId;
    return cloneState(campaign.state);
  }

  apply(action: CampaignAction): void {
    this.#assertOpen();
    const [campaignId, campaign] = this.#requireActiveCampaign();
    const next = reduceCampaign(campaign.state, action);
    const record: JsonlActionRecord = {
      version: 1,
      campaignId,
      sequence: campaign.sequence + 1,
      kind: "action",
      action,
    };
    appendDurably(this.path, record);
    campaign.state = next;
    campaign.sequence = record.sequence;
    campaign.dirty = true;
  }

  checkpoint(): CampaignState {
    this.#assertOpen();
    const [campaignId, campaign] = this.#requireActiveCampaign();
    if (campaign.dirty) this.#appendState(campaignId, "checkpoint", campaign);
    return cloneState(campaign.state);
  }

  #appendState(
    campaignId: string,
    kind: JsonlStateRecord["kind"],
    campaign: DurableCampaign,
  ): void {
    const sequence = campaign.sequence + 1;
    const state = cloneState(campaign.state);
    appendDurably(this.path, {
      version: 1,
      campaignId,
      sequence,
      kind,
      state,
      checksum: checksumState(state),
    } satisfies JsonlStateRecord);
    campaign.sequence = sequence;
    campaign.dirty = false;
  }

  #replay(): void {
    if (!existsSync(this.path)) return;
    const contents = readFileSync(this.path);
    const completeLength =
      contents.at(-1) === 0x0a ? contents.length : contents.lastIndexOf(0x0a) + 1;
    const complete = contents.subarray(0, completeLength).toString("utf8");
    if (completeLength !== contents.length) truncateSync(this.path, completeLength);
    for (const [index, line] of complete.split("\n").entries()) {
      if (!line) continue;
      let record: JsonlRecord;
      try {
        record = JSON.parse(line) as JsonlRecord;
      } catch {
        throw new Error(`Invalid campaign JSONL record on line ${index + 1}`);
      }
      assertRecord(record, index + 1);
      const current = this.#campaigns.get(record.campaignId);
      const expectedSequence = (current?.sequence ?? 0) + 1;
      if (record.sequence !== expectedSequence) {
        throw new Error(
          `Campaign ${record.campaignId} sequence ${record.sequence} is not ${expectedSequence}`,
        );
      }
      if (record.kind === "created") {
        if (current) throw new Error(`Campaign ${record.campaignId} was created more than once`);
        assertStateChecksum(record);
        this.#campaigns.set(record.campaignId, {
          state: cloneState(withRuntimeState(record.state)),
          sequence: record.sequence,
          dirty: false,
        });
      } else if (!current) {
        throw new Error(`Campaign ${record.campaignId} has no creation record`);
      } else if (record.kind === "action") {
        current.state = reduceCampaign(current.state, record.action);
        current.sequence = record.sequence;
      } else {
        assertStateChecksum(record);
        const checkpoint = withRuntimeState(record.state);
        if (checksumState(current.state) !== checksumState(checkpoint)) {
          throw new Error(`Campaign ${record.campaignId} checkpoint does not match its action log`);
        }
        current.state = cloneState(checkpoint);
        current.sequence = record.sequence;
        current.dirty = false;
      }
    }
  }

  #requireActiveCampaign(): [string, DurableCampaign] {
    if (!this.#activeCampaignId) throw new Error("Load a campaign before using the store");
    return [this.#activeCampaignId, this.#campaigns.get(this.#activeCampaignId)!];
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    closeSync(this.#lockDescriptor);
  }

  [Symbol.dispose](): void {
    this.close();
  }

  #assertOpen(): void {
    if (this.#closed) throw new Error("Campaign store is closed");
  }
}

function appendDurably(path: string, record: JsonlRecord): void {
  mkdirSync(dirname(path), { recursive: true });
  const descriptor = openSync(path, "a", 0o600);
  try {
    writeAll(descriptor, Buffer.from(`${JSON.stringify(record)}\n`, "utf8"));
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function writeAll(descriptor: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(descriptor, bytes, offset, bytes.length - offset, null);
    if (written < 1) throw new Error("Campaign log write made no forward progress");
    offset += written;
  }
}

function acquireLogLock(path: string): number {
  mkdirSync(dirname(path), { recursive: true });
  const descriptor = openSync(path, "a+", 0o600);
  try {
    const result = spawnSync("flock", ["--exclusive", "--nonblock", "3"], {
      stdio: ["ignore", "ignore", "pipe", descriptor],
      encoding: "utf8",
    });
    if (result.error) {
      throw new Error("The durable JSONL store requires the util-linux flock command", {
        cause: result.error,
      });
    }
    if (result.status !== 0) {
      throw new Error(`Campaign log is already owned by another process: ${path}`);
    }
    // Linux flock locks the open file description. Child fd 3 duplicates this parent-held
    // descriptor, so the lock remains live after the helper exits and until close().
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function checksumState(state: CampaignState): string {
  return createHash("sha256").update(JSON.stringify(state)).digest("hex");
}

function assertStateChecksum(record: JsonlStateRecord): void {
  if (checksumState(record.state) !== record.checksum) {
    throw new Error(`Campaign ${record.campaignId} checkpoint checksum mismatch`);
  }
}

function assertRecord(record: JsonlRecord, line: number): void {
  if (
    !record ||
    record.version !== 1 ||
    typeof record.campaignId !== "string" ||
    !Number.isSafeInteger(record.sequence) ||
    record.sequence < 1 ||
    !["created", "action", "checkpoint"].includes(record.kind)
  ) {
    throw new Error(`Invalid campaign JSONL record on line ${line}`);
  }
}

function assertCampaignId(campaignId: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(campaignId)) {
    throw new Error("Campaign id must be 1-128 safe filename characters");
  }
}

function cloneState(state: CampaignState): CampaignState {
  return structuredClone(state);
}
