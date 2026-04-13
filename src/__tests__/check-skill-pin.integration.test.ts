/**
 * Integration tests for skill-pin enforcement inside `node9 check` (PreToolUse).
 * Spawns the real built CLI with an isolated HOME + an isolated cwd holding
 * a CLAUDE.md the hook will pin. Requires `npm run build` first.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function runCheck(payload: object, env: Record<string, string>, cwd: string) {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'check', JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: 60000,
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
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function makeTempHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skhook-home-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode: 'standard', autoStartDaemon: false } })
  );
  return home;
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

  it('first call of a session pins skill roots and allows the tool', () => {
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**' },
        session_id: 'sess-1',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(0);
    const pins = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'skill-pins.json'), 'utf-8')
    );
    const pinnedPaths = Object.values<{ rootPath: string }>(pins.roots).map((e) => e.rootPath);
    expect(pinnedPaths).toContain(path.join(tmpProject, 'CLAUDE.md'));
    const flag = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'skill-sessions', 'sess-1.json'), 'utf-8')
    );
    expect(flag.state).toBe('verified');
  });

  it('new session after skill tamper BLOCKS and quarantines the session', () => {
    // Prime a first session.
    runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**' },
        session_id: 'prime',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    // Tamper between sessions (simulates a supply-chain swap).
    fs.writeFileSync(path.join(tmpProject, 'CLAUDE.md'), 'MALICIOUS');
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**' },
        session_id: 'drift',
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(2);
    const out = JSON.parse(r.stdout.trim().split('\n').pop()!);
    expect(out.decision).toBe('block');
    expect(out.reason).toMatch(/skill/i);
    expect(out.reason).toMatch(/pin update/);
    const flag = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'skill-sessions', 'drift.json'), 'utf-8')
    );
    expect(flag.state).toBe('quarantined');
  });

  it('corrupt skill-pins.json fails closed (blocks)', () => {
    fs.writeFileSync(path.join(tmpHome, '.node9', 'skill-pins.json'), 'not json');
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**' },
        session_id: 'corrupt',
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

  it('missing session_id skips the skill check entirely (allows, no pin file)', () => {
    const r = runCheck(
      {
        tool_name: 'glob',
        tool_input: { pattern: '**' },
        cwd: tmpProject,
        hook_event_name: 'PreToolUse',
      },
      { HOME: tmpHome },
      tmpProject
    );
    expect(r.status).toBe(0);
    expect(fs.existsSync(path.join(tmpHome, '.node9', 'skill-pins.json'))).toBe(false);
  });
});
