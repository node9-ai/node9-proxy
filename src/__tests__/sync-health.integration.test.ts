/**
 * Integration test for the policy-sync health surface (fix spec D3).
 *
 * CLAUDE.md requires an integration test for anything that writes a file and for
 * behavior that depends on HOME — recordSyncHealth writes ~/.node9/sync-health.json
 * and status/doctor gate stdout on it. Unit tests (os.homedir spy) can't catch a
 * real HOME/path/exit-code bug in the built binary, so this drives dist/cli.js.
 *
 * Requires `npm run build` first (asserts dist/cli.js exists).
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let home: string;

beforeAll(() => {
  expect(fs.existsSync(CLI), `${CLI} missing — run npm run build`).toBe(true);
});

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-synchealth-int-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

const run = (args: string[], env: Record<string, string> = {}) =>
  spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    env: {
      ...process.env,
      HOME: home,
      // isolate: no side-channel pushes, no daemon spawn during the test
      NODE9_BLAST_DISABLE: '1',
      NODE9_SCAN_DISABLE: '1',
      NODE9_POSTURE_DISABLE: '1',
      NODE9_POLICY_MIRROR_DISABLE: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      ...env,
    },
  });

describe('policy sync — health record + never-fail-open (real dist/cli.js)', () => {
  it('records a failure and does NOT drop the cached policy when the server is unreachable', () => {
    const cachePath = path.join(home, '.node9', 'rules-cache.json');
    const seededCache = JSON.stringify({
      fetchedAt: '2026-07-01T00:00:00.000Z',
      rules: [{ name: 'seed-rule', tool: '*', verdict: 'block' }],
      etag: 'seed-etag',
    });
    fs.writeFileSync(cachePath, seededCache, 'utf-8');

    const r = run(['policy', 'sync'], {
      NODE9_API_KEY: 'fake',
      NODE9_API_URL: 'http://127.0.0.1:9/policies/sync', // dead port → ECONNREFUSED
    });

    // Surfaced as a non-zero exit (a gate signal, not a crash).
    expect(r.status).not.toBe(0);
    expect(r.error).toBeUndefined();

    // Failure recorded, and crucially NO lastCheckedAt (we never reached the server).
    const health = JSON.parse(
      fs.readFileSync(path.join(home, '.node9', 'sync-health.json'), 'utf-8')
    );
    expect(health.consecutiveFailures).toBeGreaterThanOrEqual(1);
    expect(typeof health.lastError).toBe('string');
    expect(health.lastCheckedAt).toBeUndefined();

    // NEVER FAIL OPEN: the cached policy survives the failed sync untouched.
    expect(fs.readFileSync(cachePath, 'utf-8')).toBe(seededCache);
  });

  it('node9 status surfaces a STALE cloud policy (not a silent old cache)', () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'credentials.json'),
      JSON.stringify({ default: { apiKey: 'fake' } }),
      'utf-8'
    );
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { approvers: { cloud: true } } }),
      'utf-8'
    );
    fs.writeFileSync(
      path.join(home, '.node9', 'sync-health.json'),
      JSON.stringify({
        consecutiveFailures: 3,
        lastCheckedAt: '2026-07-01T00:00:00.000Z',
        lastError: 'connect ECONNREFUSED',
      }),
      'utf-8'
    );

    const r = run(['status']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Policy sync STALE/i);
  });
});
