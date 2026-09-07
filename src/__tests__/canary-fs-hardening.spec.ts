// Blockers 3 and 4 from the adversarial review: node9 deletes and overwrites
// files in the user's home on the strength of data an agent can reach.
//
// The registry (~/.node9/canaries.json) is jail-blocked, but the jail matches
// PATHS, not intent: the reviewer showed a `python3 -c` that builds the path
// from expanduser is allowed. So the registry must be treated as untrusted
// input to any destructive operation, and node9 must not believe its own
// registry when it is about to unlink or overwrite.
//
// Symlink rows skip on win32 WITH A RECORDED REASON (creating one needs
// privileges there); a check that could not run is a third state.
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');
const win = process.platform === 'win32';
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

type Rec = {
  id: string;
  kind: string;
  field: string;
  path: string;
  value: string;
  valueHash: string;
  retiredAt?: string;
  label: string;
  fileHash: string;
  createdDir: boolean;
};

let home: string;
const store = () => path.join(home, '.node9', 'canaries.json');
const readRecords = (): Rec[] =>
  (JSON.parse(fs.readFileSync(store(), 'utf-8')) as { records: Rec[] }).records;
const writeRecords = (recs: Rec[]) =>
  fs.writeFileSync(store(), JSON.stringify({ version: 1, records: recs }, null, 2) + '\n');

function cli(args: string[]) {
  const base = { ...process.env };
  delete base.NODE9_API_KEY;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 90000,
    cwd: os.tmpdir(),
    env: {
      ...base,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}
const plantAll = () => {
  const r = cli(['canary', 'plant', '--all', '--json']);
  expect(r.status, r.stderr).toBe(0);
};
const removeKind = (kind: string) => {
  const r = cli(['canary', 'remove', '--kind', kind, '--json']);
  let out: { results: Array<{ action: string; path?: string; reason?: string }> } = { results: [] };
  try {
    out = JSON.parse(r.stdout) as typeof out;
  } catch {
    /* non-JSON output on a hard failure */
  }
  return { r, res: out.results[0] };
};

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`build first: ${CLI}`);
});
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-canary-fs-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

describe('X. remove must only ever delete a path node9 would have planted', () => {
  it('X9 known-true: an untampered plant/remove cycle still works', () => {
    plantAll();
    const before = readRecords().find((x) => x.kind === 'env-file')!;
    expect(fs.existsSync(before.path)).toBe(true);
    const { r, res } = removeKind('env-file');
    expect(r.status, r.stderr).toBe(0);
    expect(res.action).toBe('removed');
    expect(fs.existsSync(before.path)).toBe(false);
  });

  it('X1 a record repointed at an unrelated file: refused, victim untouched', () => {
    plantAll();
    const victim = path.join(home, 'payroll.csv');
    fs.writeFileSync(victim, 'salary data\n');
    const victimHash = sha(fs.readFileSync(victim));
    const recs = readRecords();
    for (const rec of recs) {
      if (rec.kind !== 'env-file') continue;
      rec.path = victim;
      rec.fileHash = victimHash; // the hash is NOT a defence: the tamperer computes it
    }
    writeRecords(recs);
    const { res } = removeKind('env-file');
    expect(res.action).toBe('refused');
    expect(fs.existsSync(victim), 'the victim file must survive').toBe(true);
    expect(sha(fs.readFileSync(victim))).toBe(victimHash);
  });

  it('X2 a traversal path that escapes home: refused, nothing outside home touched', () => {
    plantAll();
    const outside = path.join(os.tmpdir(), `node9-outside-${process.pid}.txt`);
    fs.writeFileSync(outside, 'do not delete\n');
    try {
      const recs = readRecords();
      for (const rec of recs) {
        if (rec.kind !== 'env-file') continue;
        rec.path = path.join(home, 'sub', '..', '..', path.basename(outside));
        rec.fileHash = sha(fs.readFileSync(outside));
      }
      writeRecords(recs);
      const { res } = removeKind('env-file');
      expect(res.action).toBe('refused');
      expect(fs.existsSync(outside), 'a path outside home must never be removed').toBe(true);
    } finally {
      fs.rmSync(outside, { force: true });
    }
  });

  it("X3 a record repointed at ANOTHER kind's site path: refused", () => {
    plantAll();
    const sshPath = readRecords().find((x) => x.kind === 'ssh-key')!.path;
    const recs = readRecords();
    for (const rec of recs) {
      if (rec.kind !== 'env-file') continue;
      rec.path = sshPath;
      rec.fileHash = sha(fs.readFileSync(sshPath));
    }
    writeRecords(recs);
    const { res } = removeKind('env-file');
    expect(res.action).toBe('refused');
    expect(fs.existsSync(sshPath)).toBe(true);
  });

  it('X5 a decoy planted at the FALLBACK path is still removable', () => {
    // Force the fallback: make the primary exist first.
    fs.writeFileSync(path.join(home, '.env.bak'), 'user content\n');
    plantAll();
    const rec = readRecords().find((x) => x.kind === 'env-file')!;
    expect(rec.path).toBe(path.join(home, '.env.local.bak'));
    const { res } = removeKind('env-file');
    expect(res.action).toBe('removed');
    expect(fs.existsSync(rec.path)).toBe(false);
    expect(fs.readFileSync(path.join(home, '.env.bak'), 'utf-8')).toBe('user content\n');
  });
});

describe('X. the registry temp file must not be a write primitive', () => {
  it.skipIf(win)(
    'X6 a symlink pre-planted at the legacy temp name cannot be used to overwrite',
    () => {
      const victim = path.join(home, 'victim.txt');
      fs.writeFileSync(victim, 'original\n');
      const victimHash = sha(fs.readFileSync(victim));
      fs.symlinkSync(victim, path.join(home, '.node9', 'canaries.json.tmp'));
      plantAll();
      expect(fs.existsSync(victim)).toBe(true);
      expect(sha(fs.readFileSync(victim)), 'the victim must be byte-identical').toBe(victimHash);
      expect(readRecords().length).toBeGreaterThan(0);
    }
  );

  it('X7 a regular file at the legacy temp name does not break a plant', () => {
    fs.writeFileSync(path.join(home, '.node9', 'canaries.json.tmp'), 'stale\n');
    plantAll();
    expect(readRecords().length).toBe(5);
  });

  it('X8 no temp file is left behind after a successful save', () => {
    plantAll();
    const leftovers = fs.readdirSync(path.join(home, '.node9')).filter((f) => f.includes('.tmp'));
    expect(leftovers, 'a save must clean up after itself').toEqual([]);
  });

  // X8c (a failed save must not leave a temp file) lives in
  // canary-registry.spec.ts as a UNIT row. It cannot be written here: making
  // the registry path a directory to force a rename failure makes loadCanaries
  // throw EISDIR on the READ first, so saveCanaries is never reached and the
  // row passes without exercising anything. Verified before moving it.

  it('X8b the registry is still 0600 and valid JSON after the change', () => {
    plantAll();
    if (!win) expect(fs.statSync(store()).mode & 0o777).toBe(0o600);
    expect(() => JSON.parse(fs.readFileSync(store(), 'utf-8'))).not.toThrow();
  });

  it('records the reason when symlink rows cannot run', () => {
    if (!win) return;
    console.warn(
      '[canary-fs] X6 SKIPPED on win32: creating a symlink needs privileges. Symlink safety is UNVERIFIED on this platform.'
    );
    expect(win).toBe(true);
  });
});
