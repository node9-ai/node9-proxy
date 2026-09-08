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
  const gen = site.generate(); // throws if the engine would not block the shape (H18)
  // mkdirSync(recursive) returns the first path it created, or undefined when
  // the directory was already there. Asking IT is atomic; the old
  // existsSync-then-create pair could disagree with itself between the two
  // calls and mis-record whether uninstall should remove the directory
  // (CodeQL js/file-system-race). The file write below is the guard that
  // matters and is already exclusive (`wx`).
  const createdDir = fs.mkdirSync(dir, { recursive: true, mode: site.dirMode }) !== undefined;
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

/**
 * The only paths a decoy of this kind may ever occupy. `remove` compares
 * against this, not against the registry, because the registry is data an
 * agent can reach: the jail matches paths and a language runtime that builds
 * the path itself is not a watched binary. Exact equality against a two-element
 * set after path.resolve, never a prefix test: a prefix test on `~/.aws/` would
 * still permit deleting a real `~/.aws/config`.
 */
function allowedPathsFor(kind: CanaryKind, home: string): string[] {
  const site = SITES[kind];
  return [site.primary(home), site.fallback(home)].map((x) => path.resolve(x));
}

export function removeKind(kind: CanaryKind, home = os.homedir()): RemoveResult {
  const live = liveRecords(kind);
  if (live.length === 0) return { kind, action: 'absent' };
  const p = live[0].path;
  const { fileHash, createdDir } = live[0];

  // Refuse before touching the filesystem. The fileHash below answers "did this
  // file change since node9 wrote it", which is a DIFFERENT question from "is
  // node9 entitled to delete this file" — and whoever can rewrite the registry
  // computes the hash too, so it is not a defence on its own.
  //
  // Resolve the INTENDED path rather than realpath'ing what is on disk. Both are
  // safe here (unlinkSync removes a link, not its target), so this is a
  // robustness choice, not a second security boundary: the comparison should
  // not depend on an attacker-chosen link target. Stated plainly because the
  // mutation that swaps them is EQUIVALENT and no row witnesses a difference.
  if (!allowedPathsFor(kind, home).includes(path.resolve(p))) {
    return {
      kind,
      action: 'refused',
      path: p,
      reason: `${p} is not a path node9 plants a ${kind} decoy at; refusing to delete it. If you believe this is a decoy, remove it by hand.`,
    };
  }

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
