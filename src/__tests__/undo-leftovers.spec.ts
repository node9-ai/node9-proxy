// The removal notice must tell the truth about what is left on disk.
//
// Three artifacts, not one — the first design named only `snapshots/`:
//   ~/.node9/snapshots/<hash>/   the shadow git repos (the bulk)   undo.ts:143
//   ~/.node9/snapshots.json      the stack index (720 KB observed)  undo.ts:33
//   ~/.node9/undo_latest.txt     backward-compat pointer            undo.ts:48
//
// Two failure modes this file exists to prevent, both of them the same
// dishonesty the removal is meant to end:
//   R8  an EMPTY leftover directory must not nag forever — the condition is
//       "there are files", not "the directory exists".
//   R11 an unreadable subtree must NOT be silently counted as 0 bytes. Telling
//       the user with 378 GB that they have "0 MB" and then advising `rm -rf`
//       is worse than saying nothing.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { findUndoLeftovers } from '../utils/undo-leftovers';

describe('undo leftovers — an honest size or nothing', () => {
  let tmpHome: string;
  let node9Dir: string;
  let snapshotsDir: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-leftovers-'));
    node9Dir = path.join(tmpHome, '.node9');
    snapshotsDir = path.join(node9Dir, 'snapshots');
    fs.mkdirSync(node9Dir, { recursive: true });
  });

  afterEach(() => {
    // Restore any mode we stripped, or rmSync cannot descend.
    try {
      for (const entry of fs.readdirSync(snapshotsDir, { withFileTypes: true })) {
        if (entry.isDirectory()) fs.chmodSync(path.join(snapshotsDir, entry.name), 0o755);
      }
    } catch {
      /* directory may not exist in every row */
    }
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  const write = (rel: string, bytes: number) => {
    const full = path.join(node9Dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, 'x'.repeat(bytes));
  };

  // ── R9 — the common case: nothing was ever written ────────────────────────
  it('R9: no artifacts at all → null (the notice never appears)', () => {
    expect(findUndoLeftovers(tmpHome)).toBeNull();
  });

  // ── R8 — the forever-nag ──────────────────────────────────────────────────
  it('R8: an EMPTY snapshots directory → null, not "0 MB"', () => {
    fs.mkdirSync(snapshotsDir, { recursive: true });
    expect(findUndoLeftovers(tmpHome)).toBeNull();
  });

  // ── R10 — the number is real ──────────────────────────────────────────────
  it('R10: a store with files reports real bytes and a real count', () => {
    write('snapshots/abc123/a.txt', 1000);
    write('snapshots/abc123/objects/b.pack', 2500);
    const left = findUndoLeftovers(tmpHome);
    expect(left).not.toBeNull();
    expect(left!.files).toBe(2);
    expect(left!.bytes).toBe(3500);
    expect(left!.unreadable).toBe(0);
  });

  // ── R11 ⭐ the lying number ───────────────────────────────────────────────
  it('R11: an unreadable subtree is COUNTED as unreadable, never as 0 bytes', () => {
    write('snapshots/readable/a.txt', 1000);
    write('snapshots/locked/secret.pack', 5000);
    fs.chmodSync(path.join(snapshotsDir, 'locked'), 0o000);

    const left = findUndoLeftovers(tmpHome);
    expect(left).not.toBeNull();
    expect(left!.unreadable).toBeGreaterThan(0);
    // The readable part is still reported — the notice says "≥ 1000 B".
    expect(left!.bytes).toBe(1000);
  });

  // ── R12 — all three artifacts, not just the directory ─────────────────────
  it('R12: snapshots.json and undo_latest.txt are counted too', () => {
    write('snapshots/abc/a.txt', 100);
    write('snapshots.json', 720965);
    write('undo_latest.txt', 40);

    const left = findUndoLeftovers(tmpHome);
    expect(left).not.toBeNull();
    expect(left!.paths).toHaveLength(3);
    expect(left!.paths.some((p) => p.endsWith('snapshots.json'))).toBe(true);
    expect(left!.paths.some((p) => p.endsWith('undo_latest.txt'))).toBe(true);
    expect(left!.bytes).toBe(100 + 720965 + 40);
  });

  // ── R12b — the index alone still counts ───────────────────────────────────
  // A user who ran `rm -rf ~/.node9/snapshots` (the command the FIRST design
  // suggested) is left with exactly this state. The notice must still fire, or
  // the stale index survives every path in the design.
  it('R12b: snapshots.json alone, with no directory, still reports', () => {
    write('snapshots.json', 720965);
    const left = findUndoLeftovers(tmpHome);
    expect(left).not.toBeNull();
    expect(left!.paths).toHaveLength(1);
    expect(left!.bytes).toBe(720965);
  });
});
