// Canary registry: ~/.node9/canaries.json. Design: canary-design.md 4.2 and
// section 10 (H5, H8, H9, H12, H13, H19). Corpus: canary-corpus.md section C.
//
// The store holds decoy values in plaintext: they are worthless by
// construction, and the matcher needs them verbatim. What the store must not
// become is a readable MAP of the decoys, so the file is 0600 and is itself
// jail-blocked, and the jail registration happens BEFORE the first byte of
// the store is written (a malformed jail store aborts the save, C9). Only
// `valueHash` ever leaves the machine.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash, randomUUID } from 'crypto';
import { CANARY_MIN_LENGTH, type CanaryValue } from '@node9/policy-engine';
import { addJailPath, regenerateUserJail } from '../shields/jail';

export type CanaryKind = 'aws-profile' | 'env-file' | 'ssh-key';

export interface CanaryRecord {
  id: string;
  kind: CanaryKind;
  /** Which secret at the site this record is (a site can plant several). */
  field: string;
  /** Where it was planted (the created file). */
  path: string;
  /** The decoy, plaintext: it is worthless by construction. Never reaches audit or SaaS. */
  value: string;
  /** sha256 hex of the exact value bytes: the ONLY value-derived field that may leave the machine. */
  valueHash: string;
  plantedAt: string;
  retiredAt?: string;
  /** The plausible section/var name used at the site; never contains canary or node9. */
  label: string;
  /** sha256 hex of the created file as written, so remove can refuse if it changed. */
  fileHash: string;
  /** Whether plant created the parent directory (remove may then delete it if empty). */
  createdDir: boolean;
}

export type NewCanaryRecord = Omit<CanaryRecord, 'id' | 'valueHash' | 'plantedAt' | 'retiredAt'>;

export const sha256Hex = (s: string | Buffer): string =>
  createHash('sha256').update(s).digest('hex');

export function canaryStorePath(): string {
  return path.join(os.homedir(), '.node9', 'canaries.json');
}

function isRecord(x: unknown): x is CanaryRecord {
  if (!x || typeof x !== 'object') return false;
  const r = x as Record<string, unknown>;
  return typeof r.id === 'string' && typeof r.value === 'string' && typeof r.valueHash === 'string';
}

/** Missing file: []. Malformed JSON: throw, never clobber (mirrors readJailPaths).
 *  Malformed records are dropped, well-formed ones kept, nothing is written. Retired
 *  records are included by default: the matcher must still see them. */
export function loadCanaries(opts?: { includeRetired?: boolean }): CanaryRecord[] {
  const p = canaryStorePath();
  let raw: string;
  try {
    raw = fs.readFileSync(p, 'utf-8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw e;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(
      `[node9] ${p} is not valid JSON; refusing to touch it (${e instanceof Error ? e.message : String(e)})`
    );
  }
  const recs = (parsed as { records?: unknown } | null)?.records;
  if (!Array.isArray(recs)) return [];
  const out = recs.filter(isRecord);
  return opts?.includeRetired === false ? out.filter((r) => !r.retiredAt) : out;
}

/** Jail first, then write: the store is never on disk unjailed. 0600, atomic rename. */
export function saveCanaries(records: CanaryRecord[]): void {
  const p = canaryStorePath();
  const paths = addJailPath(p, 'block'); // throws on a malformed jail store: nothing written below
  regenerateUserJail(paths); // addJailPath alone writes the store without materialising the shield (H9)
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, records }, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, p);
}

export function registerCanary(rec: NewCanaryRecord): CanaryRecord {
  if (typeof rec.value !== 'string' || rec.value.length < CANARY_MIN_LENGTH) {
    throw new Error(`[node9] a canary value must be at least ${CANARY_MIN_LENGTH} characters`);
  }
  const full: CanaryRecord = {
    ...rec,
    id: randomUUID(),
    valueHash: sha256Hex(rec.value),
    plantedAt: new Date().toISOString(),
  };
  saveCanaries([...loadCanaries(), full]);
  return full;
}

/** Keeps the record (an old value must stay matchable and attributable), stamps retiredAt. */
export function retireCanary(id: string): CanaryRecord | null {
  const all = loadCanaries();
  const r = all.find((x) => x.id === id);
  if (!r) return null;
  r.retiredAt = new Date().toISOString();
  saveCanaries(all);
  return r;
}

/** The matcher's input, read fresh on every call (the daemon must not cache it, H13). */
export function canaryValues(): CanaryValue[] {
  return loadCanaries().map((r) => ({ id: r.id, value: r.value, retired: Boolean(r.retiredAt) }));
}
