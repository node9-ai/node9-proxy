/**
 * The package check on the shipped binary: `node9 check` with a Claude Code
 * PreToolUse payload for a Bash install, against a local OSV index written
 * into a temp HOME. NODE9_TESTING=1 with no URL overrides means the registry
 * and OSV online are never contacted, so these rows exercise the index path
 * and the fail-open path exactly.
 *
 * Package names and advisory ids are canaries, not real packages.
 * Requirements: `npm run build` first (dist/cli.js).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';
import { keySafeEnv } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const itCli = it.skipIf(!fs.existsSync(CLI));

let home: string;

function writeIndex(eco: 'npm' | 'PyPI', name: string, entries: object[]): void {
  const dir = path.join(home, '.node9', 'osv', eco);
  const shard = createHash('sha1').update(name).digest('hex').slice(0, 2);
  fs.mkdirSync(path.join(dir, 'shards'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'shards', `${shard}.json`), JSON.stringify({ [name]: entries }));
  fs.writeFileSync(
    path.join(dir, 'meta.json'),
    JSON.stringify({
      syncedAt: new Date().toISOString(),
      lastModifiedMs: 0,
      records: 1,
      mode: 'full',
    })
  );
}

function check(command: string, config: object = {}) {
  fs.writeFileSync(path.join(home, '.node9', 'config.json'), JSON.stringify(config));
  const payload = {
    hook_event_name: 'PreToolUse',
    session_id: 'pkg-check-it',
    cwd: home,
    tool_name: 'Bash',
    tool_input: { command },
  };
  const r = spawnSync(process.execPath, [CLI, 'check', JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: home,
    env: keySafeEnv({
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_NPM_REGISTRY_URL: undefined,
      NODE9_PYPI_URL: undefined,
      NODE9_OSV_API_URL: undefined,
    }),
  });
  expect(r.error).toBeUndefined();
  return r;
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-pkgcheck-it-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('node9 check — package check before install', () => {
  itCli('blocks a known malicious npm package, advisory id in the agent-facing reason', () => {
    writeIndex('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', versions: ['1.0.0'] }]);
    const r = check('cd app && npm install node9-canary-mal@1.0.0');
    expect(r.status).toBe(2);
    const out = JSON.parse(r.stdout);
    expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain('MAL-0000-0001');
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain('node9-canary-mal@1.0.0');
    const audit = fs.readFileSync(path.join(home, '.node9', 'audit.log'), 'utf8');
    expect(audit).toContain('package-malicious');
  });

  itCli('blocks a malicious PyPI package under its normalised name', () => {
    writeIndex('PyPI', 'node9-canary-py', [{ id: 'MAL-0000-0002', all: true }]);
    const r = check('python3 -m pip install Node9_Canary.Py');
    expect(r.status).toBe(2);
    expect(r.stdout).toContain('MAL-0000-0002');
  });

  itCli('asks for review when the record covers other versions and the version is unknown', () => {
    writeIndex('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', versions: ['9.9.9'] }]);
    const r = check('npx node9-canary-mal');
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain('MAL-0000-0001');
  });

  itCli('allows a package the fresh index does not list', () => {
    writeIndex('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', all: true }]);
    const r = check('npm install node9-canary-clean@1.0.0');
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain('deny');
  });

  itCli('fails open with no index and no network, and records the miss', () => {
    const r = check('npm install node9-canary-mal@1.0.0');
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain('deny');
    const debug = fs.readFileSync(path.join(home, '.node9', 'hook-debug.log'), 'utf8');
    expect(debug).toContain('package-check-miss');
    expect(debug).toContain('node9-canary-mal');
  });

  itCli('policy.packageCheck.enabled=false turns the check off', () => {
    writeIndex('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', all: true }]);
    const r = check('npm install node9-canary-mal', {
      policy: { packageCheck: { enabled: false } },
    });
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain('MAL-0000-0001');
  });

  itCli('policy.packageCheck.allow exempts a package by glob', () => {
    writeIndex('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', all: true }]);
    const r = check('npm install node9-canary-mal', {
      policy: { packageCheck: { allow: ['node9-canary-*'] } },
    });
    expect(r.status).toBe(0);
  });
});
