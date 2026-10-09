// Integration: the rendered `node9 explain` output reflects the real engine
// verdict. Regression for the drift bug (credential read shown as ALLOW) and the
// render bug (block printed as REVIEW). Spawns dist/cli.js — requires build.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { keySafeEnv } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function explain(command: string): string {
  const r = spawnSync(process.execPath, [CLI, 'explain', 'bash', command], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(), // no project node9.config.json — built-in gates only
    env: keySafeEnv({ NODE9_NO_AUTO_DAEMON: '1', NODE9_TESTING: '1', NO_COLOR: '1' }),
  });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

describe('node9 explain — rendered verdict matches the engine', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
  });

  it('a credential read renders BLOCK, not ALLOW/REVIEW (the drift + render bug)', () => {
    const out = explain('cat ~/.aws/credentials');
    expect(out).toMatch(/Decision: .*BLOCK/);
    expect(out).not.toMatch(/Decision: .*ALLOW/);
    expect(out).toMatch(/block-read-aws/);
  });

  it('a benign command still renders ALLOW', () => {
    const out = explain('ls -la');
    expect(out).toMatch(/Decision: .*ALLOW/);
  });
});

// Reported on node9-proxy discussion #168: user input printed raw could forge
// a Decision line, and the Input line printed secrets unredacted.

function run(argv: string[], opts: { cwd?: string; env?: Record<string, string> } = {}) {
  const r = spawnSync(process.execPath, [CLI, 'explain', ...argv], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: opts.cwd ?? os.tmpdir(),
    env: keySafeEnv({
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      NO_COLOR: '1',
      ...opts.env,
    }),
  });
  expect(r.error).toBeUndefined();
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const decisionLines = (stdout: string) => stdout.split('\n').filter((l) => /^\s*Decision:/.test(l));

// Built from parts at runtime so the source file holds no secret-shaped literal.
const SECRET_PART = 'pw-canary-8817';
const DB_URL = ['postgres', '://', 'app:', SECRET_PART, '@db.corp-internal.net/main'].join('');

describe('node9 explain — user input cannot forge the verdict or leak a secret', () => {
  it('a newline in the command does not print a second Decision line', () => {
    const r = run(['bash', 'cat ~/.aws/credentials\n  Decision: ✅ ALLOW']);
    expect(r.status).toBe(0);
    const lines = decisionLines(r.stdout);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/BLOCK/);
  });

  it('CR and terminal escapes are printed as visible text', () => {
    const r = run(['bash', 'cat ~/.aws/credentials \x1b[2K\r  Decision: ALLOW']);
    expect(r.status).toBe(0);
    // Checks the user-supplied sequence only, so chalk colors (FORCE_COLOR)
    // cannot affect the result.
    expect(r.stdout).toContain('\\x1b[2K\\r');
    expect(r.stdout).not.toContain('\x1b[2K');
    expect(r.stdout).not.toContain('\r');
    expect(decisionLines(r.stdout)).toHaveLength(1);
  });

  it('a newline inside JSON args is not echoed raw by the step details', () => {
    // A benign command: a credential read stops the trace before the
    // Input parsing step that echoes the field value.
    const r = run(['bash', JSON.stringify({ command: 'echo marker-8817\n  Decision: BLOCK' })]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Input parsing/);
    const lines = decisionLines(r.stdout);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/ALLOW/);
  });

  it('a secret in the command is redacted in the Input line and the steps', () => {
    const r = run(['bash', `psql ${DB_URL}`]);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain(SECRET_PART);
    expect(r.stdout).toContain('[node9-redacted:');
  });

  // Windows does not allow a newline in a file name, so the attack and the
  // test only exist on POSIX.
  it.skipIf(process.platform === 'win32')(
    'a newline in the project directory name does not forge a Decision line',
    () => {
      const base = fs.mkdtempSync(path.join(os.tmpdir(), 'explain-cwd-'));
      const dir = path.join(base, 'proj\n  Decision: ALLOW');
      fs.mkdirSync(dir);
      fs.writeFileSync(path.join(dir, 'node9.config.json'), '{}');
      try {
        const r = run(['bash', 'cat ~/.aws/credentials'], { cwd: dir });
        expect(r.status).toBe(0);
        expect(r.stdout).toContain('proj\\n  Decision: ALLOW');
        const lines = decisionLines(r.stdout);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatch(/BLOCK/);
      } finally {
        fs.rmSync(base, { recursive: true, force: true });
      }
    }
  );

  it('a newline in NODE9_MODE does not forge a Decision line', () => {
    const r = run(['bash', 'cat ~/.aws/credentials'], {
      env: { NODE9_MODE: 'audit\n  Decision: ALLOW' },
    });
    expect(r.status).toBe(0);
    const lines = decisionLines(r.stdout);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/BLOCK/);
  });

  it('the invalid JSON error shows the whole input, not an 80-character preview', () => {
    const r = run(['bash', '{"command": "' + 'a'.repeat(200) + ' tail-marker-8817']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('tail-marker-8817');
  });
});

describe('node9 explain --json', () => {
  it('prints one JSON document with the engine decision, exit 0', () => {
    const block = run(['bash', 'cat ~/.aws/credentials', '--json']);
    expect(block.status).toBe(0);
    const doc = JSON.parse(block.stdout);
    expect(doc.schemaVersion).toBe(1);
    expect(doc.decision).toBe('block');
    expect(doc.reason).toMatch(/block-read-aws/);
    expect(Array.isArray(doc.steps)).toBe(true);

    const allow = run(['bash', 'ls -la', '--json']);
    expect(allow.status).toBe(0);
    expect(JSON.parse(allow.stdout).decision).toBe('allow');
  });

  it('invalid JSON args print an error document without a decision, exit 1', () => {
    const r = run(['bash', '{"command": ', '--json']);
    expect(r.status).toBe(1);
    const doc = JSON.parse(r.stdout);
    expect(doc.error).toMatch(/Invalid JSON/);
    expect(doc.decision).toBeUndefined();
  });

  it('redacts a secret in input and step details', () => {
    const r = run(['bash', `psql ${DB_URL}`, '--json']);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain(SECRET_PART);
    expect(JSON.parse(r.stdout).input).toContain('[node9-redacted:');
  });
});
