/**
 * Integration tests for skill-pin enforcement inside `node9 check` (PreToolUse).
 *
 * Spawns the real built CLI with an isolated HOME + an isolated cwd holding
 * a CLAUDE.md the hook will pin. Verifies the full first-call → subsequent →
 * drift-block → quarantine-sticks pipeline runs end-to-end.
 *
 * Requires `npm run build` before running.
 */

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

function runCheck(
  payload: object,
  env: Record<string, string> = {},
  cwd = os.tmpdir(),
  timeoutMs = 60000
): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const result = spawnSync(process.execPath, [CLI, 'check', JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: timeoutMs,
    cwd,
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      FORCE_COLOR: '0',
      ...env,
      ...(env.HOME != null ? { USERPROFILE: env.HOME } : {}),
    },
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function makeTempHome(): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skhook-home-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  // Minimal config — mode 'standard', daemon disabled
  fs.writeFileSync(
    path.join(node9Dir, 'config.json'),
    JSON.stringify({ settings: { mode: 'standard', autoStartDaemon: false } })
  );
  return tmpHome;
}

function makeTempProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skhook-proj-'));
  fs.writeFileSync(path.join(dir, 'CLAUDE.md'), 'original skill content\n');
  return dir;
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found at ${CLI} — run \`npm run build\` first.`);
  }
});

describe('skill-pin enforcement in `node9 check`', () => {
  let tmpHome: string;
  let tmpProject: string;
  beforeEach(() => {
    tmpHome = makeTempHome();
    tmpProject = makeTempProject();
  });
  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(tmpProject, { recursive: true, force: true });
  });

  it('first call of a session pins all skill roots and allows the tool', () => {
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'first-session',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(0);
    // Pin file written
    const pinsPath = path.join(tmpHome, '.node9', 'skill-pins.json');
    expect(fs.existsSync(pinsPath)).toBe(true);
    const pins = JSON.parse(fs.readFileSync(pinsPath, 'utf-8'));
    // At least the project's CLAUDE.md should be pinned
    const pinnedPaths = Object.values<{ rootPath: string }>(pins.roots).map((e) => e.rootPath);
    expect(pinnedPaths).toContain(path.join(tmpProject, 'CLAUDE.md'));
    // Verified flag written for this session
    const flag = path.join(tmpHome, '.node9', 'skill-sessions', 'first-session.json');
    expect(fs.existsSync(flag)).toBe(true);
    const flagData = JSON.parse(fs.readFileSync(flag, 'utf-8'));
    expect(flagData.state).toBe('verified');
  });

  it('subsequent call of the same session short-circuits (no re-hash; allows)', () => {
    // Prime the session
    runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'persist-sess',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    // Mutate CLAUDE.md — but since the session is already verified, the hook
    // should NOT re-check (short-circuit on the verified flag).
    fs.writeFileSync(path.join(tmpProject, 'CLAUDE.md'), 'CHANGED AFTER VERIFICATION');
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'persist-sess',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(0);
  });

  it('new session with unchanged skills re-verifies and allows', () => {
    runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'sess-A',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'sess-B',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(0);
  });

  it('new session with drifted skills BLOCKS and quarantines the session', () => {
    // Prime
    runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'sess-prime',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    // Tamper CLAUDE.md BEFORE the next session starts (simulates a supply-chain swap)
    fs.writeFileSync(path.join(tmpProject, 'CLAUDE.md'), 'MALICIOUS CONTENT');

    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'sess-drift',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(2);
    // JSON block payload on stdout
    const out = JSON.parse(r.stdout.trim().split('\n').pop()!);
    expect(out.decision).toBe('block');
    expect(out.reason).toMatch(/skill/i);
    expect(out.reason).toMatch(/pin update/);
    // Quarantine flag persisted
    const flagPath = path.join(tmpHome, '.node9', 'skill-sessions', 'sess-drift.json');
    expect(fs.existsSync(flagPath)).toBe(true);
    const flag = JSON.parse(fs.readFileSync(flagPath, 'utf-8'));
    expect(flag.state).toBe('quarantined');
  });

  it('subsequent call in a quarantined session blocks immediately (no re-hash)', () => {
    // Prime + drift
    runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'sess-prime2',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    fs.writeFileSync(path.join(tmpProject, 'CLAUDE.md'), 'TAMPERED');
    runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'q-sess',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    // Repair the skill — but the session should still be quarantined
    fs.writeFileSync(path.join(tmpProject, 'CLAUDE.md'), 'original skill content\n');
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'q-sess',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(2);
    const out = JSON.parse(r.stdout.trim().split('\n').pop()!);
    expect(out.decision).toBe('block');
    expect(out.reason).toMatch(/quarantine/i);
  });

  it('corrupt skill-pins.json fails closed (blocks)', () => {
    fs.writeFileSync(path.join(tmpHome, '.node9', 'skill-pins.json'), 'not json');
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'corrupt-sess',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(2);
    const out = JSON.parse(r.stdout.trim().split('\n').pop()!);
    expect(out.decision).toBe('block');
    expect(out.reason).toMatch(/corrupt|skill/i);
  });

  it('missing session_id skips the skill check entirely', () => {
    // Without a session_id we have no key to scope verification; fall through
    // to normal authorization (which, for an ignored tool, should allow).
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(0);
    // No pin file created (hook skipped)
    const pinsPath = path.join(tmpHome, '.node9', 'skill-pins.json');
    expect(fs.existsSync(pinsPath)).toBe(false);
  });

  it('relative cwd is rejected for project-scoped skill roots (global roots still pinned)', () => {
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**/*.ts' },
        session_id: 'rel-sess',
        cwd: 'relative/path', // NOT absolute — must be ignored per CLAUDE.md rules
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(0);
    // A verified flag is still written (global roots hashed fine)
    const flag = path.join(tmpHome, '.node9', 'skill-sessions', 'rel-sess.json');
    expect(fs.existsSync(flag)).toBe(true);
    // Crucially, NO project-scoped root entries (all pinned roots are under $HOME)
    const pinsPath = path.join(tmpHome, '.node9', 'skill-pins.json');
    if (fs.existsSync(pinsPath)) {
      const pins = JSON.parse(fs.readFileSync(pinsPath, 'utf-8'));
      for (const entry of Object.values<{ rootPath: string }>(pins.roots)) {
        expect(entry.rootPath.startsWith(tmpHome)).toBe(true);
      }
    }
  });
});
