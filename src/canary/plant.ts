// Plant / remove / status / rotate. Design: canary-design.md 4.3, 4.5 and
// section 10 (H9, H19, H20). Corpus: canary-corpus.md section D.
//
// Rule zero: node9 never modifies an existing credential file. Every planted
// file is one node9 created (opened with `wx`, so a race cannot turn a create
// into an overwrite). Remove deletes only that file, refuses if its content
// hash changed, and removes the parent directory only if node9 created it and
// it is empty now.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { addJailPath, regenerateUserJail, removeJailPath } from '../shields/jail';
import {
  loadCanaries,
  registerCanary,
  retireCanary,
  sha256Hex,
  type CanaryKind,
  type CanaryRecord,
} from './registry';
import { SITES, ALL_KINDS } from './sites';

export interface PlantResult {
  kind: CanaryKind;
  action: 'created' | 'exists' | 'skipped';
  path: string;
  createdDir: boolean;
  reason?: string;
  recordIds: string[];
}
export interface RemoveResult {
  kind: CanaryKind;
  action: 'removed' | 'already-gone' | 'refused' | 'absent';
  path?: string;
  reason?: string;
  dirRemoved?: boolean;
}
export interface SiteStatus {
  kind: CanaryKind;
  state: 'planted' | 'missing' | 'absent';
  path?: string;
  records: number;
  plantedAt?: string;
}

const liveRecords = (kind: CanaryKind): CanaryRecord[] =>
  loadCanaries().filter((r) => r.kind === kind && !r.retiredAt);

const fileHashOf = (p: string): string | null => {
  try {
    return sha256Hex(fs.readFileSync(p));
  } catch {
    return null;
  }
};

export function plantKind(kind: CanaryKind, home = os.homedir()): PlantResult {
  const site = SITES[kind];
  const live = liveRecords(kind);
  if (live.length > 0) {
    const p = live[0].path;
    if (fileHashOf(p) === live[0].fileHash) {
      return {
        kind,
        action: 'exists',
        path: p,
        createdDir: live[0].createdDir,
        recordIds: live.map((r) => r.id),
      };
    }
    // The file is gone or changed under us: those records are retired and we plant fresh.
    for (const r of live) retireCanary(r.id);
  }

  const primary = site.primary(home);
  const fallback = site.fallback(home);
  let target: string;
  if (!fs.existsSync(primary) && !site.preferFallback?.(home)) target = primary;
  else if (!fs.existsSync(fallback)) target = fallback;
  else {
    return {
      kind,
      action: 'skipped',
      path: primary,
      createdDir: false,
      reason: `both ${primary} and ${fallback} exist; node9 never writes into an existing file`,
      recordIds: [],
    };
  }

  const dir = path.dirname(target);
  const createdDir = !fs.existsSync(dir);
  const gen = site.generate(); // throws if the engine would not block the shape (H18)
  if (createdDir) fs.mkdirSync(dir, { recursive: true, mode: site.dirMode });
  fs.writeFileSync(target, gen.text, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(target, 0o600);
  const fileHash = sha256Hex(gen.text);

  // Jail the planted path so the read is also blocked; materialise, not only store (H9).
  regenerateUserJail(addJailPath(target, 'block'));

  const recordIds = gen.values.map(
    (v) =>
      registerCanary({
        kind,
        field: v.field,
        path: target,
        value: v.value,
        label: gen.label,
        fileHash,
        createdDir,
      }).id
  );
  return { kind, action: 'created', path: target, createdDir, recordIds };
}

export function removeKind(kind: CanaryKind): RemoveResult {
  const live = liveRecords(kind);
  if (live.length === 0) return { kind, action: 'absent' };
  const p = live[0].path;
  const { fileHash, createdDir } = live[0];

  if (!fs.existsSync(p)) {
    for (const r of live) retireCanary(r.id);
    unjail(p);
    return { kind, action: 'already-gone', path: p };
  }
  if (fileHashOf(p) !== fileHash) {
    // The value may still be on disk in whatever the file became: keep the records live.
    return {
      kind,
      action: 'refused',
      path: p,
      reason: `${p} changed since node9 wrote it; inspect and remove it by hand`,
    };
  }
  fs.unlinkSync(p);
  let dirRemoved = false;
  if (createdDir) {
    const dir = path.dirname(p);
    try {
      if (fs.readdirSync(dir).length === 0) {
        fs.rmdirSync(dir);
        dirRemoved = true;
      }
    } catch {
      /* leave it */
    }
  }
  unjail(p);
  for (const r of live) retireCanary(r.id);
  return { kind, action: 'removed', path: p, dirRemoved };
}

function unjail(p: string): void {
  try {
    const { paths } = removeJailPath(p);
    regenerateUserJail(paths);
  } catch {
    /* a stale jail entry for an absent file is harmless */
  }
}

export function statusAll(): SiteStatus[] {
  return ALL_KINDS.map((kind) => {
    const live = liveRecords(kind);
    if (live.length === 0) return { kind, state: 'absent', records: 0 };
    const p = live[0].path;
    return {
      kind,
      state: fs.existsSync(p) ? 'planted' : 'missing',
      path: p,
      records: live.length,
      plantedAt: live[0].plantedAt,
    };
  });
}

export function rotateKind(
  kind: CanaryKind,
  home = os.homedir()
): { removed: RemoveResult; planted?: PlantResult } {
  const removed = removeKind(kind);
  if (removed.action === 'refused') return { removed };
  return { removed, planted: plantKind(kind, home) };
}
