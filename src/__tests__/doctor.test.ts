/**
 * Integration tests for `node9 doctor`.
 * Spawns the built CLI binary with a controlled HOME directory so we can
 * assert on stdout/stderr and exit codes without touching real user files.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NODE = process.execPath;

/** Run `node9 doctor` with an isolated HOME. Returns stdout+stderr and exit code. */
function runDoctor(homeDir: string, cwd?: string): { output: string; exitCode: number } {
  const result = spawnSync(NODE, [CLI, 'doctor'], {
    env: { ...process.env, HOME: homeDir, USERPROFILE: homeDir, NODE9_TESTING: '1' },
    cwd: cwd ?? homeDir,
    encoding: 'utf-8',
  });
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  return { output, exitCode: result.status ?? 1 };
}

/** Write a JSON file, creating parent dirs as needed. */
function writeJson(filePath: string, data: unknown) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

let tmpBase: string;

beforeAll(() => {
  // One temp directory per test run — subdirs created per-test
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-doctor-test-'));
});

// ── Binary checks ─────────────────────────────────────────────────────────────

describe('node9 doctor — binary section', () => {
  it('always passes Node.js and git checks (they exist in CI)', () => {
    const home = path.join(tmpBase, 'empty');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Node\.js/);
    expect(output).toMatch(/git version/);
  });
});

// ── Config checks ─────────────────────────────────────────────────────────────

describe('node9 doctor — configuration section', () => {
  it('warns (not fails) when global config is missing', () => {
    const home = path.join(tmpBase, 'no-config');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    expect(output).toMatch(/config\.json not found/);
    expect(output).toMatch(/⚠️/);
  });

  it('passes when valid global config exists', () => {
    const home = path.join(tmpBase, 'valid-config');
    writeJson(path.join(home, '.node9', 'config.json'), { settings: { mode: 'standard' } });
    const { output } = runDoctor(home);
    expect(output).toMatch(/config\.json found and valid/);
  });

  it('fails when global config is invalid JSON', () => {
    const home = path.join(tmpBase, 'bad-config');
    const configDir = path.join(home, '.node9');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, 'config.json'), 'this is not json');
    const { output, exitCode } = runDoctor(home);
    expect(output).toMatch(/invalid JSON/);
    expect(output).toMatch(/❌/);
    expect(exitCode).toBe(1);
  });

  it('reports cloud credentials when present', () => {
    const home = path.join(tmpBase, 'with-creds');
    writeJson(path.join(home, '.node9', 'config.json'), { settings: {} });
    writeJson(path.join(home, '.node9', 'credentials.json'), { default: { apiKey: 'test' } });
    const { output } = runDoctor(home);
    expect(output).toMatch(/credentials found/i);
  });

  it('warns (not fails) when credentials are missing', () => {
    const home = path.join(tmpBase, 'no-creds');
    writeJson(path.join(home, '.node9', 'config.json'), { settings: {} });
    const { output } = runDoctor(home);
    expect(output).toMatch(/local-only mode/i);
    expect(output).not.toMatch(/❌.*credentials/);
  });
});

// ── Hook checks ───────────────────────────────────────────────────────────────

describe('node9 doctor — agent hooks section', () => {
  it('passes Claude hook check when PreToolUse hook contains node9', () => {
    const home = path.join(tmpBase, 'claude-ok');
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: {
        PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
      },
    });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Claude Code.*PreToolUse hook active/);
  });

  it('fails Claude hook check when settings.json has no node9 hook', () => {
    const home = path.join(tmpBase, 'claude-bad');
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: { PreToolUse: [{ matcher: '.*', hooks: [{ command: 'some-other-tool' }] }] },
    });
    const { output, exitCode } = runDoctor(home);
    expect(output).toMatch(/Claude Code.*hook missing/);
    expect(exitCode).toBe(1);
  });

  it('warns (not fails) when Claude settings.json is absent', () => {
    const home = path.join(tmpBase, 'claude-absent');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Claude Code.*not configured/);
    // Absent = warning only, not ❌
    expect(output).not.toMatch(/❌.*Claude/);
  });

  it('passes Gemini hook check when BeforeTool hook contains node9', () => {
    const home = path.join(tmpBase, 'gemini-ok');
    writeJson(path.join(home, '.gemini', 'settings.json'), {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ command: 'node9 check' }] }],
      },
    });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Gemini CLI.*BeforeTool hook active/);
  });

  it('passes Cursor hook check when preToolUse contains node9', () => {
    const home = path.join(tmpBase, 'cursor-ok');
    writeJson(path.join(home, '.cursor', 'hooks.json'), {
      version: 1,
      hooks: { preToolUse: [{ command: 'node9 check' }] },
    });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Cursor.*preToolUse hook active/);
  });
});

// ── Summary ───────────────────────────────────────────────────────────────────

describe('node9 doctor — summary', () => {
  it('exits 0 and prints "All checks passed" when everything is configured', () => {
    const home = path.join(tmpBase, 'all-good');
    writeJson(path.join(home, '.node9', 'config.json'), { settings: { mode: 'standard' } });
    writeJson(path.join(home, '.node9', 'credentials.json'), { default: { apiKey: 'k' } });
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: {
        PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
      },
    });
    writeJson(path.join(home, '.gemini', 'settings.json'), {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ command: 'node9 check' }] }],
      },
    });
    writeJson(path.join(home, '.cursor', 'hooks.json'), {
      version: 1,
      hooks: { preToolUse: [{ command: 'node9 check' }] },
    });

    const { output, exitCode } = runDoctor(home);
    expect(output).toMatch(/All checks passed/);
    expect(exitCode).toBe(0);
  });

  it('exits 1 and prints failure count when checks fail', () => {
    const home = path.join(tmpBase, 'has-failures');
    const configDir = path.join(home, '.node9');
    fs.mkdirSync(configDir, { recursive: true });
    // Bad JSON → failure
    fs.writeFileSync(path.join(configDir, 'config.json'), '{bad json}');

    const { output, exitCode } = runDoctor(home);
    expect(output).toMatch(/check\(s\) failed/);
    expect(exitCode).toBe(1);
  });

  it('prints version in header', () => {
    const home = path.join(tmpBase, 'version-check');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Node9 Doctor\s+v\d+\.\d+\.\d+/);
  });
});
