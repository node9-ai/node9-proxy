// src/daemon/audit-shipper.ts
//
// The outbox shipper ("the mailman"). The local audit.log is the durable
// outbox — every decision row is written there first (fast, offline-safe).
// This module delivers those rows to the SaaS in batches, advancing an
// acknowledged watermark only after a 200. The batch endpoint dedups on each
// row's `eid`, so delivery is at-least-once + idempotent = exactly-once
// effect: re-sending any chunk is always safe.
//
// This replaces the old decision-time POSTs (fire-and-forget on block paths
// — killed by process.exit before the fetch completed — and an awaited POST
// on the allow path that taxed every tool call with a network round-trip).
//
// Modeled on daemon/scan-watermark.ts: tick → read after watermark → push →
// persist position.
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { LOCAL_AUDIT_LOG, HOOK_DEBUG_LOG, appendToLog } from '../audit/index.js';
import { getConfig } from '../config/index.js';
import { readCredentials } from './sync.js';
import { validateApiUrl } from '../auth/cloud.js';

export const AUDIT_SHIP_WATERMARK = path.join(os.homedir(), '.node9', 'audit-ship.json');

const DEFAULT_INTERVAL_MS = 20_000;
const MAX_BATCH = 500; // mirror of the SaaS Zod cap
const MAX_CHUNK_BYTES = 4 * 1024 * 1024; // bound per-tick memory on big backlogs
const MAX_CHUNKS_PER_TICK = 10;
const FETCH_TIMEOUT_MS = 10_000;

/**
 * Rows the SaaS must NOT receive:
 * - 'ignored' — read/grep/glob noise; deliberately never synced (pre-shipper
 *   behavior, keeps cloud volume sane).
 *
 * Rows whose decision had a pending /intercept entry need linkage, not a
 * blanket skip: the SaaS already holds a BE-origin AuditLog row for that
 * request — true whichever racer decided it (cloud, native popup, terminal).
 * The linkage key is cloudRequestId:
 * - row HAS cloudRequestId  → ship it; the BE ENRICHES its origin row (sets
 *   clientEventId) instead of inserting — exact count, no duplicate.
 * - 'cloud' row WITHOUT it  → legacy/pre-wire row; unlinkable, skip to avoid
 *   double-counting the BE-origin row.
 */
const SKIP_CHECKED_BY = new Set(['ignored']);

export interface Watermark {
  /** Identity of the log file the offset belongs to — guards rotation. */
  fileSig: string;
  /** Byte offset of the first UNSHIPPED byte. */
  offset: number;
  lastEid?: string;
  updatedAt: string;
}

/** Wire row for POST /audit/batch — field names mirror the local logbook. */
export interface WireRow {
  eid: string;
  ts: string;
  tool: string;
  args?: Record<string, unknown>;
  argsHash?: string;
  /** Redacted display string for hash-mode rows (see buildArgsPreview). */
  argsPreview?: string;
  decision: 'allow' | 'deny';
  checkedBy?: string;
  ruleName?: string;
  agent?: string;
  mcpServer?: string;
  sessionId?: string;
  dlpPattern?: string;
  dlpSample?: string;
  /** Linkage to the BE-origin AuditLog row written at /intercept time —
   *  the BE enriches that row instead of inserting a duplicate. */
  cloudRequestId?: string;
  /** Context — where the action ran (event-detail Context block). */
  workingDir?: string;
  platform?: string;
  shellType?: string;
  /** Phase B — rich per-event detail for batch-only rows: touched file path,
   *  loop magnitude, and the session transcript pointer. */
  editFilePath?: string;
  loopCount?: number;
  transcriptPath?: string;
  /** Phase D2 — taint provenance on taint-based block rows (causal edge). */
  taintFromEid?: string;
  taintSource?: string;
}

/** Identity of the log file, so a rotated/recreated log resets the offset
 *  (re-shipping is safe: the SaaS dedups on eid). Hashes the FIRST LINE
 *  only — appends never change it, a new file's first row always does.
 *  (Hashing a fixed byte-count would be unstable while the first line is
 *  shorter than the window: the next append would shift the hash.) */
export function fileSignature(filePath: string): string {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(512);
    const read = fs.readSync(fd, buf, 0, 512, 0);
    const slice = buf.subarray(0, read);
    const nl = slice.indexOf(0x0a);
    const firstLine = nl === -1 ? slice : slice.subarray(0, nl);
    return crypto.createHash('sha256').update(firstLine).digest('hex').slice(0, 16);
  } finally {
    fs.closeSync(fd);
  }
}

export function readWatermark(watermarkPath: string): Watermark | null {
  try {
    const raw = JSON.parse(fs.readFileSync(watermarkPath, 'utf-8')) as Watermark;
    if (typeof raw.fileSig === 'string' && typeof raw.offset === 'number' && raw.offset >= 0)
      return raw;
  } catch {}
  return null;
}

export function writeWatermark(watermarkPath: string, wm: Watermark): void {
  // tmp + rename: a crash mid-write must never corrupt the position.
  const tmp = `${watermarkPath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(wm));
  fs.renameSync(tmp, watermarkPath);
}

/**
 * Parse a chunk of the logbook into wire rows.
 * - Complete lines only — a partially-written tail line stays for next tick.
 * - Skips rows without an eid (pre-shipper history), testRun rows, and the
 *   SKIP_CHECKED_BY families.
 * Returns the rows plus the byte length actually consumed (offset delta).
 */
export function buildWireRows(chunk: Buffer): { rows: WireRow[]; consumed: number } {
  const lastNl = chunk.lastIndexOf(0x0a); // '\n'
  if (lastNl === -1) return { rows: [], consumed: 0 };
  const complete = chunk.subarray(0, lastNl + 1);
  const rows: WireRow[] = [];
  for (const line of complete.toString('utf-8').split('\n')) {
    if (!line.trim()) continue;
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue; // torn/corrupt line — skip, never wedge the shipper
    }
    if (typeof parsed.eid !== 'string' || parsed.eid.length < 8) continue;
    if (typeof parsed.tool !== 'string' || !parsed.tool) continue;
    if (parsed.decision !== 'allow' && parsed.decision !== 'deny') continue;
    // No ts = malformed row; skipping beats fabricating an event time.
    if (typeof parsed.ts !== 'string') continue;
    if (parsed.testRun === true) continue;
    const checkedBy = typeof parsed.checkedBy === 'string' ? parsed.checkedBy : undefined;
    if (checkedBy && SKIP_CHECKED_BY.has(checkedBy)) continue;
    const cloudRequestId =
      typeof parsed.cloudRequestId === 'string' ? parsed.cloudRequestId : undefined;
    // Cloud-resolved row without a linkage key: the BE-origin row is the
    // record; shipping an unlinkable copy would double-count it.
    if (checkedBy === 'cloud' && !cloudRequestId) continue;
    rows.push({
      eid: parsed.eid,
      ts: parsed.ts,
      tool: parsed.tool,
      ...(parsed.args && typeof parsed.args === 'object'
        ? { args: parsed.args as Record<string, unknown> }
        : {}),
      ...(typeof parsed.argsHash === 'string' ? { argsHash: parsed.argsHash } : {}),
      ...(typeof parsed.argsPreview === 'string' ? { argsPreview: parsed.argsPreview } : {}),
      decision: parsed.decision,
      ...(checkedBy ? { checkedBy } : {}),
      ...(typeof parsed.ruleName === 'string' ? { ruleName: parsed.ruleName } : {}),
      ...(typeof parsed.agent === 'string' ? { agent: parsed.agent } : {}),
      ...(typeof parsed.mcpServer === 'string' ? { mcpServer: parsed.mcpServer } : {}),
      ...(typeof parsed.sessionId === 'string' ? { sessionId: parsed.sessionId } : {}),
      ...(typeof parsed.dlpPattern === 'string' ? { dlpPattern: parsed.dlpPattern } : {}),
      ...(typeof parsed.dlpSample === 'string' ? { dlpSample: parsed.dlpSample } : {}),
      ...(cloudRequestId ? { cloudRequestId } : {}),
      ...(typeof parsed.workingDir === 'string' ? { workingDir: parsed.workingDir } : {}),
      ...(typeof parsed.platform === 'string' ? { platform: parsed.platform } : {}),
      ...(typeof parsed.shellType === 'string' ? { shellType: parsed.shellType } : {}),
      // Phase B — rich detail; forwarded only when the writer recorded it
      // (older audit.log rows simply omit them).
      ...(typeof parsed.editFilePath === 'string' ? { editFilePath: parsed.editFilePath } : {}),
      ...(typeof parsed.loopCount === 'number' ? { loopCount: parsed.loopCount } : {}),
      ...(typeof parsed.transcriptPath === 'string'
        ? { transcriptPath: parsed.transcriptPath }
        : {}),
      ...(typeof parsed.taintFromEid === 'string' ? { taintFromEid: parsed.taintFromEid } : {}),
      ...(typeof parsed.taintSource === 'string' ? { taintSource: parsed.taintSource } : {}),
    });
  }
  return { rows, consumed: lastNl + 1 };
}

/**
 * Resolve the batch-ingest endpoint from a credentials apiUrl.
 *
 * REGRESSION GUARD: the shipper gets creds from sync.ts readCredentials(),
 * which rewrites the stored base URL to its OWN route (`…/intercept` →
 * `…/intercept/policies/sync`). The first release naively appended
 * `/audit/batch` to that and 404'd on every tick — silently, forever
 * (found live, not by tests: every unit test injected deps.creds).
 * Normalize here so the endpoint is correct from EITHER URL shape.
 */
export function buildBatchEndpoint(rawApiUrl: string): string | null {
  const validated = validateApiUrl(rawApiUrl);
  if (!validated) return null;
  const base = validated
    .toString()
    .replace(/\/$/, '')
    .replace(/\/policies\/sync$/, '');
  return `${base}/audit/batch`;
}

export interface ShipDeps {
  auditLogPath?: string;
  watermarkPath?: string;
  fetchImpl?: typeof fetch;
  /** Injected for tests; production reads the merged config. */
  cloudEnabled?: boolean;
  creds?: { apiKey: string; apiUrl: string } | null;
}

export interface ShipResult {
  status: 'shipped' | 'idle' | 'disabled' | 'no-creds' | 'error';
  shipped: number;
}

/** One shipping pass: drain up to MAX_CHUNKS_PER_TICK chunks of the backlog. */
export async function shipOnce(deps: ShipDeps = {}): Promise<ShipResult> {
  const auditLogPath = deps.auditLogPath ?? LOCAL_AUDIT_LOG;
  const watermarkPath = deps.watermarkPath ?? AUDIT_SHIP_WATERMARK;
  const fetchImpl = deps.fetchImpl ?? fetch;

  let cloudEnabled = deps.cloudEnabled;
  if (cloudEnabled === undefined) {
    try {
      const settings = getConfig().settings;
      // One rule, no surprises: ship everything when logged in + cloud
      // enabled (+ shipper not explicitly disabled), nothing otherwise.
      cloudEnabled = settings.shipper.enabled !== false && settings.approvers.cloud;
    } catch {
      cloudEnabled = false;
    }
  }
  if (!cloudEnabled) return { status: 'disabled', shipped: 0 };

  const creds = deps.creds !== undefined ? deps.creds : readCredentials();
  if (!creds?.apiKey) return { status: 'no-creds', shipped: 0 };
  const endpoint = buildBatchEndpoint(creds.apiUrl);
  if (!endpoint) return { status: 'no-creds', shipped: 0 };

  if (!fs.existsSync(auditLogPath)) return { status: 'idle', shipped: 0 };

  let shipped = 0;
  try {
    for (let chunkN = 0; chunkN < MAX_CHUNKS_PER_TICK; chunkN++) {
      const size = fs.statSync(auditLogPath).size;
      if (size === 0) break;
      const sig = fileSignature(auditLogPath);
      const wm = readWatermark(watermarkPath);
      // Rotation / truncation / first run → start from 0. Re-shipping old
      // rows is safe (eid dedup); losing position is not.
      const offset = wm && wm.fileSig === sig && wm.offset <= size ? wm.offset : 0;
      if (offset >= size) break; // caught up

      const toRead = Math.min(size - offset, MAX_CHUNK_BYTES);
      const buf = Buffer.alloc(toRead);
      const fd = fs.openSync(auditLogPath, 'r');
      let read: number;
      try {
        read = fs.readSync(fd, buf, 0, toRead, offset);
      } finally {
        fs.closeSync(fd);
      }
      const { rows, consumed } = buildWireRows(buf.subarray(0, read));
      if (consumed === 0) break; // partial line only — wait for the writer

      // Ship in <=MAX_BATCH sub-batches. Any failure aborts the tick WITHOUT
      // advancing the watermark — the whole chunk re-ships next tick and the
      // SaaS dedups what already landed.
      for (let i = 0; i < rows.length; i += MAX_BATCH) {
        const batch = rows.slice(i, i + MAX_BATCH);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        try {
          const res = await fetchImpl(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${creds.apiKey}`,
            },
            body: JSON.stringify({ rows: batch }),
            signal: controller.signal,
          });
          if (!res.ok) throw new Error(`audit/batch HTTP ${res.status}`);
        } finally {
          clearTimeout(timer);
        }
        shipped += batch.length;
      }

      writeWatermark(watermarkPath, {
        fileSig: sig,
        offset: offset + consumed,
        lastEid: rows.length > 0 ? rows[rows.length - 1].eid : wm?.lastEid,
        updatedAt: new Date().toISOString(),
      });

      if (consumed < toRead) break; // partial tail line — wait for the writer
      // consumed === toRead with zero rows = a full chunk of filtered noise
      // (e.g. an 'ignored' backlog) — keep draining within this tick rather
      // than degrading to one chunk per 20s. Bounded by MAX_CHUNKS_PER_TICK.
    }
  } catch (err) {
    // Network/SaaS failures are normal (offline, deploys) — log quietly and
    // retry next tick. The watermark guarantees nothing is skipped.
    try {
      appendToLog(HOOK_DEBUG_LOG, {
        ts: new Date().toISOString(),
        shipper: 'error',
        message: (err as Error).message,
      });
    } catch {}
    return { status: 'error', shipped };
  }

  return { status: shipped > 0 ? 'shipped' : 'idle', shipped };
}

/** Shipping lag for `node9 doctor` / `status`: bytes not yet acknowledged. */
export function shipLagBytes(
  auditLogPath: string = LOCAL_AUDIT_LOG,
  watermarkPath: string = AUDIT_SHIP_WATERMARK
): number | null {
  try {
    if (!fs.existsSync(auditLogPath)) return 0;
    const size = fs.statSync(auditLogPath).size;
    const wm = readWatermark(watermarkPath);
    if (!wm) return size;
    if (wm.fileSig !== fileSignature(auditLogPath)) return size; // rotated
    return Math.max(0, size - wm.offset);
  } catch {
    return null;
  }
}

let shipperStarted = false;

/** Start the periodic shipper inside the daemon (idempotent). */
export function startAuditShipper(): void {
  if (shipperStarted) return;
  shipperStarted = true;
  const intervalMs = (() => {
    try {
      const sec = getConfig().settings.shipper.intervalSeconds;
      return sec >= 5 ? sec * 1000 : DEFAULT_INTERVAL_MS;
    } catch {
      return DEFAULT_INTERVAL_MS;
    }
  })();
  // First pass shortly after boot (catch up a backlog), then steady ticks.
  setTimeout(() => void shipOnce(), 3_000);
  setInterval(() => void shipOnce(), intervalMs);
}
