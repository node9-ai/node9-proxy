// The undo feature is removed — end-to-end, against the real built CLI.
//
// CLAUDE.md requires integration coverage for anything that touches a file
// write or HOME. This touches both, and the unit rows in undo-pin.spec.ts
// cannot see the two things that matter most here: whether the PostToolUse hook
// still WRITES, and whether the surfaces a user actually runs say anything.
//
// ⭐ R7 is the row for the reader that fails open. log.ts gates the Bash
// snapshot on `enableUndo !== false`, and `undefined !== false` is TRUE.
//
// HONESTY: R7 is GREEN today. The field is never actually absent, because
// DEFAULT_CONFIG seeds `enableUndo: false` into every merge — so `!== false`
// currently reads a real `false` and does not write. This is a LATENT bug, not
// a live one, and R7 is a regression guard rather than a bug reproduction. Its
// value is the mutation in doc/undo-removal-commit1-spec.md §3: delete
// DEFAULT_CONFIG's `enableUndo: false` and R7 must STAY green. Before the
// `=== true` fix that mutation turns R7 red; after it, R7 holds. Do not read
// this row's green as evidence that the reader was ever safe.
//
// ⭐ R13 must run with git PRESENT. The only undo string in doctor.ts today sits
// inside the `catch` of `execSync('git --version')`, so a notice written there
// is invisible to everyone who has git — that is, to every user the feature
// ever worked for.
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function run(args: string[], tmpHome: string, cwd = os.tmpdir()): RunResult {
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    cwd,
    timeout: 60000,
    env: {
      ...env,
      HOME: tmpHome,
      USERPROFILE: tmpHome,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
    },
  });
  // A silent spawn failure must never pass as a green test.
  expect(r.error).toBeUndefined();
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function makeTempHome(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-undo-rm-'));
  fs.mkdirSync(path.join(dir, '.node9'), { recursive: true });
  return dir;
}

function seedLeftovers(tmpHome: string): void {
  const snap = path.join(tmpHome, '.node9', 'snapshots', 'abc123');
  fs.mkdirSync(snap, { recursive: true });
  fs.writeFileSync(path.join(snap, 'pack.bin'), 'x'.repeat(4 * 1024 * 1024));
  fs.writeFileSync(path.join(tmpHome, '.node9', 'snapshots.json'), '[]');
  fs.writeFileSync(path.join(tmpHome, '.node9', 'undo_latest.txt'), 'deadbeef');
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found — run 'npm run build' first`);
  }
  // Control for R13/R14: these rows are only meaningful when git IS installed,
  // because the bug they guard hides on the git-missing branch.
  const git = spawnSync('git', ['--version'], { encoding: 'utf-8' });
  expect(git.status).toBe(0);
});

describe('undo removed — end to end', () => {
  let tmpHome: string;
  let tmpCwd: string;

  beforeEach(() => {
    tmpHome = makeTempHome();
    tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-undo-cwd-'));
  });

  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(tmpCwd, { recursive: true, force: true });
  });

  // ── R7 ⭐ the reader that fails open ──────────────────────────────────────
  it('R7: a PostToolUse Bash hook writes NOTHING when enableUndo is absent', () => {
    // No config file at all — the field is absent, not false. Today log.ts reads
    // `undefined !== false` as ENABLED and writes.
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'snapshots.json'),
      JSON.stringify([
        { hash: 'prior000', tool: 'Edit', argsSummary: 'a.ts', cwd: tmpCwd, timestamp: Date.now() },
      ])
    );

    const r = run(
      [
        'log',
        JSON.stringify({
          tool_name: 'Bash',
          tool_input: { command: 'echo hello > output.txt' },
          cwd: tmpCwd,
        }),
      ],
      tmpHome,
      tmpCwd
    );

    expect(r.status).toBe(0);
    expect(fs.existsSync(path.join(tmpHome, '.node9', 'snapshots'))).toBe(false);
  });

  // ── R6 — the same, with a stored `true` ───────────────────────────────────
  it('R6: a stored enableUndo:true does not resurrect the write path', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } })
    );
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'snapshots.json'),
      JSON.stringify([
        { hash: 'prior000', tool: 'Edit', argsSummary: 'a.ts', cwd: tmpCwd, timestamp: Date.now() },
      ])
    );

    const r = run(
      [
        'log',
        JSON.stringify({
          tool_name: 'Bash',
          tool_input: { command: 'echo hello > output.txt' },
          cwd: tmpCwd,
        }),
      ],
      tmpHome,
      tmpCwd
    );

    expect(r.status).toBe(0);
    expect(fs.existsSync(path.join(tmpHome, '.node9', 'snapshots'))).toBe(false);
  });

  // ── R16 — `node9 undo` announces the removal ──────────────────────────────
  it('R16: node9 undo says removed and names all three artifacts', () => {
    seedLeftovers(tmpHome);
    const r = run(['undo'], tmpHome, tmpCwd);
    expect(r.status).toBe(0);
    const out = r.stdout + r.stderr;
    expect(out.toLowerCase()).toContain('removed');
    expect(out).toContain('snapshots.json');
    expect(out).toContain('undo_latest.txt');
    // The text must not still be telling people how to switch it on.
    expect(out).not.toContain('"enableUndo": true');
  });

  // ── R15 — status ──────────────────────────────────────────────────────────
  it('R15: node9 status reports leftovers when present', () => {
    seedLeftovers(tmpHome);
    const out = run(['status'], tmpHome, tmpCwd).stdout;
    expect(out.toLowerCase()).toContain('removed');
  });

  it('R15b: node9 status says nothing about undo when there are no leftovers', () => {
    const out = run(['status'], tmpHome, tmpCwd).stdout;
    expect(out.toLowerCase()).not.toContain('undo');
  });

  // ── R13 ⭐ doctor, with git present ───────────────────────────────────────
  it('R13: node9 doctor reports the leftover store (git installed)', () => {
    seedLeftovers(tmpHome);
    const out = run(['doctor'], tmpHome, tmpCwd).stdout;
    expect(out.toLowerCase()).toContain('snapshot');
    // Control: doctor really did reach the git check on this machine, so a
    // green result cannot come from doctor having bailed out early.
    expect(out.toLowerCase()).toContain('git');
  });

  it('R14: node9 doctor says nothing when there are no leftovers', () => {
    const out = run(['doctor'], tmpHome, tmpCwd).stdout;
    expect(out.toLowerCase()).not.toContain('snapshot');
  });

  it('R13b: doctor no longer recommends git FOR UNDO', () => {
    const out = run(['doctor'], tmpHome, tmpCwd).stdout;
    expect(out).not.toContain('snapshot-based undo');
  });

  // ── R17 / R18 — the agent must not see three dead tools ───────────────────
  it('R17: the MCP tool list contains no undo tools', () => {
    const req =
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) +
      '\n' +
      JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) +
      '\n';
    const r = spawnSync(process.execPath, [CLI, 'mcp-server'], {
      encoding: 'utf-8',
      input: req,
      timeout: 60000,
      cwd: tmpCwd,
      env: {
        ...process.env,
        HOME: tmpHome,
        USERPROFILE: tmpHome,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
      },
    });
    expect(r.error).toBeUndefined();
    const out = r.stdout ?? '';
    // Control: the list came back at all and holds a tool we did NOT remove.
    expect(out).toContain('node9_status');
    expect(out).not.toContain('node9_undo_list');
    expect(out).not.toContain('node9_undo_detail');
    expect(out).not.toContain('node9_undo_revert');
  });
});
