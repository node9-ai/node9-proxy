// Integration: the rendered `node9 explain` output reflects the real engine
// verdict. Regression for the drift bug (credential read shown as ALLOW) and the
// render bug (block printed as REVIEW). Spawns dist/cli.js — requires build.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
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

  it('includes the package check step (fw#395)', () => {
    // A command that installs nothing: no registry or OSV lookup is needed,
    // so this stays offline and still proves the step reaches the output.
    const r = run(['bash', 'ls -la', '--json']);
    expect(r.status).toBe(0);
    const doc = JSON.parse(r.stdout);
    expect(doc.steps).toContainEqual(
      expect.objectContaining({ name: 'Package check', outcome: 'skip' })
    );
    expect(doc.decision).toBe('allow');
  });

  it('redacts a secret in input and step details', () => {
    const r = run(['bash', `psql ${DB_URL}`, '--json']);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain(SECRET_PART);
    expect(JSON.parse(r.stdout).input).toContain('[node9-redacted:');
  });
});

// node9Firewall#405: explain runs the hook's stateless gates in the hook's
// order. Each row below proves the built CLI runs the gate (not a skip step
// that would print the same whether or not the check ran): a malicious
// package from a seeded local OSV index, with no network; the PII gate; the
// inline-code check honouring its value at Soft.

function makeHome(config: Record<string, unknown>): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-explain-gates-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(path.join(home, '.node9', 'config.json'), JSON.stringify(config));
  return home;
}

/** A local OSV index with one MAL record covering every version of `name`. */
function seedOsvIndex(home: string, name: string): void {
  const dir = path.join(home, '.node9', 'osv', 'npm');
  fs.mkdirSync(path.join(dir, 'shards'), { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'meta.json'),
    JSON.stringify({
      syncedAt: new Date().toISOString(),
      lastModifiedMs: Date.now(),
      records: 1,
      mode: 'full',
    })
  );
  const key = name.toLowerCase();
  const shard = createHash('sha1').update(key).digest('hex').slice(0, 2);
  fs.writeFileSync(
    path.join(dir, 'shards', `${shard}.json`),
    JSON.stringify({ [key]: [{ id: 'MAL-0000-node9-test', all: true }] })
  );
}

const homeEnv = (home: string) => ({ HOME: home, USERPROFILE: home });

describe('node9 explain runs the gates the hook runs (node9Firewall#405)', () => {
  it('a malicious package in the local index is BLOCK before the engine, offline', () => {
    const home = makeHome({
      policy: { packageCheck: { newPackage: 'off', installScript: 'off', onlineFallback: false } },
    });
    seedOsvIndex(home, 'node9-test-only-malicious-pkg');
    const r = run(['bash', 'npm install node9-test-only-malicious-pkg@1.0.0', '--json'], {
      env: homeEnv(home),
    });
    expect(r.status).toBe(0);
    const doc = JSON.parse(r.stdout);
    expect(doc.decision).toBe('block');
    expect(doc.reason).toContain('Package Check');
    expect(doc.steps).toContainEqual(
      expect.objectContaining({ name: 'Package check', outcome: 'block', final: true })
    );
    expect(doc.steps).toContainEqual(
      expect.objectContaining({ name: 'Engine verdict (authoritative)', outcome: 'skip' })
    );
    expect(JSON.stringify(doc.steps)).toContain('MAL-0000-node9-test');
  });

  it('the PII gate is shown and stops the call; off, the same call is allowed', () => {
    // A Luhn-valid test card number, built from parts.
    const card = ['4111', '1111', '1111', '1111'].join(' ');
    const on = run(['bash', `echo ${card} > out.txt`, '--json'], { env: homeEnv(makeHome({})) });
    expect(on.status).toBe(0);
    const onDoc = JSON.parse(on.stdout);
    expect(onDoc.decision).toBe('block');
    expect(onDoc.reason).toContain('PII');
    expect(onDoc.steps).toContainEqual(
      expect.objectContaining({ name: 'PII gate', outcome: 'block', final: true })
    );
    expect(onDoc.steps).toContainEqual(
      expect.objectContaining({ name: 'Package check', outcome: 'skip' })
    );

    const off = run(['bash', `echo ${card} > out.txt`, '--json'], {
      env: homeEnv(makeHome({ policy: { dlp: { pii: 'off' } } })),
    });
    const offDoc = JSON.parse(off.stdout);
    expect(offDoc.decision).toBe('allow');
    expect(offDoc.steps).toContainEqual(
      expect.objectContaining({ name: 'PII gate', outcome: 'skip' })
    );
  });

  it('at Soft, dangerous inline code is logged, not shown as a stop above an allow', () => {
    const script = 'python3 -c \'import os; os.remove("/var/tmp/x")\'';
    const soft = run(['bash', script, '--json'], {
      env: homeEnv(makeHome({ settings: { mode: 'soft' } })),
    });
    const doc = JSON.parse(soft.stdout);
    expect(doc.decision).toBe('allow');
    const inline = doc.steps.find((s: { name: string }) => s.name === 'Inline execution');
    expect(inline).toMatchObject({ outcome: 'allow' });
    expect(inline.final).not.toBe(true);
    expect(doc.steps.filter((s: { final?: boolean }) => s.final).length).toBeLessThanOrEqual(1);

    const standard = run(['bash', script, '--json'], { env: homeEnv(makeHome({})) });
    expect(JSON.parse(standard.stdout).decision).toBe('review');
  });
});
