// `node9 undo --purge` — the command that deletes what the removed feature left.
//
// This is the ONLY code in the undo-removal arc that deletes a user's data, so
// the rows below are weighted toward the guards rather than the happy path:
//
//   P5  we delete exactly the three artifacts and nothing else — config.json,
//       the audit log and the credentials in the same directory must survive.
//   P6  unattended runs must refuse. `preuninstall` runs `node9 uninstall`
//       without a TTY; nothing in that shape may delete a user's snapshots.
//   P7  a symlinked artifact is skipped, never followed. Otherwise a
//       ~/.node9/snapshots symlink would turn a cleanup into a delete of
//       whatever it points at.
//   P8  `force: true` swallows a permission failure, so a post-delete verify is
//       what stands between us and printing a false success.
//
// The corpus was written before the implementation — the whole feature it
// replaces shipped without one and the review found eight defects in it.
//
// ⚠️ Mode-dependent rows are skipped on Windows (chmod maps only to the
// read-only attribute there and does not block access). This is the repo's
// existing convention — see config-patch.spec.ts:169 and
// skill-pin.unit.test.ts:183 — and ignoring it is what would have reddened
// Windows CI on the previous attempt.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { undoLeftoverPaths } from '../utils/undo-leftovers';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const onPosix = process.platform !== 'win32';

let tmpHome: string;
const madeReadOnly: string[] = [];

function node9(...parts: string[]): string {
  return path.join(tmpHome, '.node9', ...parts);
}

beforeEach(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-purge-'));
  fs.mkdirSync(node9(), { recursive: true });
});

afterEach(() => {
  // Restore any mode we changed before rm, or the cleanup itself fails.
  for (const p of madeReadOnly.splice(0)) {
    try {
      fs.chmodSync(p, 0o755);
    } catch {
      /* already gone */
    }
  }
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

/** All three artifacts, with content, exactly as the feature left them. */
function seedAll(): { store: string; index: string; pointer: string } {
  const store = node9('snapshots');
  fs.mkdirSync(path.join(store, 'abc123'), { recursive: true });
  fs.writeFileSync(path.join(store, 'abc123', 'pack.bin'), 'x'.repeat(2048));
  const index = node9('snapshots.json');
  fs.writeFileSync(index, '[]');
  const pointer = node9('undo_latest.txt');
  fs.writeFileSync(pointer, 'deadbeef');
  return { store, index, pointer };
}

/** The neighbours in ~/.node9 that a purge must never touch. */
function seedBystanders(): string[] {
  const files = [node9('config.json'), node9('audit.log'), node9('credentials.json')];
  fs.writeFileSync(files[0], '{"settings":{}}');
  fs.writeFileSync(files[1], 'audit row\n');
  fs.writeFileSync(files[2], '{"token":"x"}');
  return files;
}

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** spawnSync gives a non-TTY stdin, which is exactly the unattended shape P6 needs. */
function run(args: string[]): RunResult {
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    cwd: os.tmpdir(),
    timeout: 60000,
    env: {
      ...env,
      HOME: tmpHome,
      USERPROFILE: tmpHome,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
    },
  });
  // CLAUDE.md: assert BOTH. A silent spawn failure must never read as green,
  // and three rows below assert on ABSENT output — a crash with empty stdout
  // would satisfy them.
  expect(r.error).toBeUndefined();
  expect(r.status).not.toBeNull();
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

describe('undoLeftoverPaths — which artifacts are still on disk', () => {
  it('P1: returns nothing on a machine that never enabled the feature', () => {
    expect(undoLeftoverPaths(tmpHome)).toEqual([]);
  });

  it('P2: returns all three, store first', () => {
    const { store, index, pointer } = seedAll();
    expect(undoLeftoverPaths(tmpHome)).toEqual([store, index, pointer]);
  });

  it('P3: returns undo_latest.txt alone — the artifact the first design missed', () => {
    const pointer = node9('undo_latest.txt');
    fs.writeFileSync(pointer, 'deadbeef');
    expect(undoLeftoverPaths(tmpHome)).toEqual([pointer]);
  });

  it.skipIf(!onPosix)('P4: an unreadable store is still reported, not read as absent', () => {
    const store = node9('snapshots');
    fs.mkdirSync(path.join(store, 'abc'), { recursive: true });
    fs.writeFileSync(path.join(store, 'abc', 'blob'), 'x'.repeat(1024));
    fs.chmodSync(store, 0o000);
    madeReadOnly.push(store);
    // existsSync returns false on EACCES, which is how the previous
    // implementation went silent on a machine whose store was present and large.
    expect(undoLeftoverPaths(tmpHome)).toEqual([store]);
  });

  it('P4b: an EMPTY snapshots directory is still an artifact worth removing', () => {
    const store = node9('snapshots');
    fs.mkdirSync(store, { recursive: true });
    expect(undoLeftoverPaths(tmpHome)).toEqual([store]);
  });
});

describe('node9 undo --purge', () => {
  it('P5: deletes exactly the three artifacts and leaves the rest of ~/.node9 alone', () => {
    const { store, index, pointer } = seedAll();
    const bystanders = seedBystanders();

    const r = run(['undo', '--purge', '--yes']);

    expect(r.status).toBe(0);
    expect(fs.existsSync(store)).toBe(false);
    expect(fs.existsSync(index)).toBe(false);
    expect(fs.existsSync(pointer)).toBe(false);
    for (const f of bystanders) expect(fs.existsSync(f)).toBe(true);
    // ~/.node9 itself is not ours to remove — `node9 uninstall --purge` owns that.
    expect(fs.existsSync(node9())).toBe(true);
  });

  it('P6: refuses without a TTY and without --yes, and deletes nothing', () => {
    const { store, index, pointer } = seedAll();

    const r = run(['undo', '--purge']);

    expect(r.status).toBe(1);
    expect(`${r.stdout}${r.stderr}`).toMatch(/--yes/);
    expect(fs.existsSync(store)).toBe(true);
    expect(fs.existsSync(index)).toBe(true);
    expect(fs.existsSync(pointer)).toBe(true);
  });

  it.skipIf(!onPosix)('P7: skips a symlinked artifact and never deletes its target', () => {
    const target = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-target-'));
    const keep = path.join(target, 'precious.txt');
    fs.writeFileSync(keep, "a copy of the user's own code");
    fs.symlinkSync(target, node9('snapshots'), 'dir');
    fs.writeFileSync(node9('undo_latest.txt'), 'deadbeef');

    try {
      const r = run(['undo', '--purge', '--yes']);

      // The symlink is reported as skipped, and BOTH it and its target survive.
      expect(`${r.stdout}${r.stderr}`).toMatch(/symlink/i);
      expect(fs.existsSync(keep)).toBe(true);
      expect(fs.lstatSync(node9('snapshots')).isSymbolicLink()).toBe(true);
      // The non-symlink artifact is still removed in the same run.
      expect(fs.existsSync(node9('undo_latest.txt'))).toBe(false);
      // A skipped artifact is an incomplete purge, so the exit code says so.
      expect(r.status).toBe(1);
    } finally {
      fs.rmSync(target, { recursive: true, force: true });
    }
  });

  it.skipIf(!onPosix)('P8: reports what survived instead of a false success', () => {
    fs.writeFileSync(node9('undo_latest.txt'), 'deadbeef');
    // rmSync({force:true}) swallows the EACCES; only a post-delete check sees it.
    fs.chmodSync(node9(), 0o555);
    madeReadOnly.push(node9());

    const r = run(['undo', '--purge', '--yes']);

    expect(r.status).toBe(1);
    expect(`${r.stdout}${r.stderr}`).toMatch(/undo_latest\.txt/);
    fs.chmodSync(node9(), 0o755);
    expect(fs.existsSync(node9('undo_latest.txt'))).toBe(true);
  });

  it('P8b: says there is nothing to remove, and exits 0, on a clean machine', () => {
    const r = run(['undo', '--purge', '--yes']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/nothing/i);
  });
});

describe('node9 undo — the flags that used to exist', () => {
  it('P9: --list and --all answer the question and exit 0', () => {
    for (const flag of ['--list', '--all']) {
      const r = run(['undo', flag]);
      expect(r.status).toBe(0);
      expect(r.stdout).toMatch(/removed/i);
      expect(r.stderr).not.toMatch(/unknown option/);
    }
  });

  it('P10: --steps asked for a revert that did not happen, so it exits 1', () => {
    const r = run(['undo', '--steps', '2']);
    expect(r.status).toBe(1);
    expect(`${r.stdout}${r.stderr}`).toMatch(/removed/i);
    expect(r.stderr).not.toMatch(/unknown option/);
  });

  it('P11: bare `node9 undo` explains the removal and exits 0', () => {
    const r = run(['undo']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/removed/i);
  });
});
