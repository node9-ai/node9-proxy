/**
 * Task #17 — Phase 0 acceptance harness (the design's definitive gate).
 *
 * The confirmed PRIMARY root cause (daemon-enforcement-nondeterminism-design.md
 * §1b): a hook's getConfig() read of ~/.node9/rules-cache.json overlapping a
 * daemon writeCache() got a torn/partial file → JSON.parse threw inside a
 * fail-OPEN catch → EVERY cloud-mandated protection (shields, managed mode)
 * silently vanished for that call → a shield-blocked command was ALLOWED.
 * Non-deterministic (overlap-dependent) and fail-open.
 *
 * The design was explicit that unit tests are insufficient here — "unit tests
 * pass while the live gate fails open" — and mandated a real-subprocess probe:
 * "mandate a shield the device lacks; N non-interactive probes of its block
 * target → assert 0 allows." This is that test, run against the REAL wired gate
 * (`dist/cli.js check`), NOT a mocked reader.
 *
 * Reproduction of the race at the gate: a background NON-ATOMIC writer thrashes
 * rules-cache.json between a truncated (invalid-JSON) and a complete state — a
 * strictly harsher writer than the real daemon's occasional writeCache. If the
 * two fixes hold (atomic write + resilient read w/ last-good fallback), every
 * probe of the mandated shield's block target is denied. On the pre-fix code
 * (fail-open catch, no retry, no last-good) a probe whose read caught the torn
 * primary would drop the aws shield and allow `aws s3 rb`.
 *
 * Requirements: `npm run build` first (asserts dist/cli.js). No daemon needed
 * (probes run in-process via NODE9_NO_AUTO_DAEMON); no port contention.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync, spawn, type ChildProcess } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

// `aws s3 rb …` matches shield:aws:block-delete-s3-bucket (verdict: block).
const BLOCK_PROBE = {
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command: 'aws s3 rb s3://phase0-victim-bucket --force' },
};

const CACHE_FULL = JSON.stringify({
  fetchedAt: '2026-07-01T00:00:00Z',
  workspaceId: 'ws-phase0',
  shields: ['aws'], // a builtin the device does not locally activate — mandated via cloud cache
  rules: [],
});

function makeHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-phase0-'));
  const n9 = path.join(home, '.node9');
  fs.mkdirSync(n9, { recursive: true });
  fs.writeFileSync(
    path.join(n9, 'config.json'),
    JSON.stringify({ settings: { mode: 'standard', autoStartDaemon: false } })
  );
  fs.writeFileSync(path.join(n9, 'rules-cache.json'), CACHE_FULL);
  // The daemon's last-known-good sibling — the reader's fallback when the
  // primary is caught mid-write. The thrasher NEVER touches this file, so a
  // resilient reader always has a clean shield source to fall back to.
  fs.writeFileSync(path.join(n9, 'rules-cache.last-good.json'), CACHE_FULL);
  return home;
}

function runCheck(home: string): { status: number | null; stdout: string; stderr: string } {
  const env = { ...process.env } as Record<string, string>;
  delete env.NODE9_API_KEY; // never hit the real API
  delete env.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'check', JSON.stringify(BLOCK_PROBE)], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(), // don't load the repo's own node9.config.json
    env: {
      ...env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1', // approval racers return early — never wait for a human
      NODE9_NO_AUTO_DAEMON: '1', // in-process gate; the thrasher plays the daemon-writer role
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

// A separate OS process that hammers rules-cache.json non-atomically between an
// invalid (truncated) and a complete state. Real concurrency with the spawnSync
// probes (which block THIS event loop but not another process).
const THRASH_SRC = `
const fs = require('fs'), path = require('path');
const cache = path.join(process.env.HOME, '.node9', 'rules-cache.json');
const full = ${JSON.stringify(CACHE_FULL)};
const torn = full.slice(0, Math.floor(full.length * 0.6)); // invalid JSON
while (true) {
  try { fs.writeFileSync(cache, torn); fs.writeFileSync(cache, full); } catch (_) {}
}
`;

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found — run "npm run build" first. Expected: ${CLI}`);
  }
});

describe('task #17 Phase 0 — a mandated shield block never fails open (real gate)', () => {
  it('control: the mandated aws shield blocks `aws s3 rb` (exit 2) with a clean cache', () => {
    const home = makeHome();
    try {
      const r = runCheck(home);
      // Proves the setup actually enforces — otherwise "0 allows" below is vacuous.
      expect(r.status).toBe(2); // exit 2 = block; exit 0 = allow
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  }, 60000);

  it('N=20 probes under a concurrent non-atomic cache thrasher → ZERO allows', async () => {
    const home = makeHome();
    let thrasher: ChildProcess | null = null;
    try {
      thrasher = spawn(process.execPath, ['-e', THRASH_SRC], {
        env: { ...process.env, HOME: home, USERPROFILE: home },
        stdio: 'ignore',
      });
      await new Promise((r) => setTimeout(r, 150)); // let the thrash loop get going

      const statuses: (number | null)[] = [];
      for (let i = 0; i < 20; i++) statuses.push(runCheck(home).status);

      const allows = statuses.filter((s) => s === 0);
      // THE INVARIANT: a cloud-mandated hard block, probed non-interactively, is
      // never resolved to allow — not once in 20 reads racing a torn writer.
      expect(allows).toEqual([]);
      // And it genuinely enforced (blocked/held), not errored into some other code.
      expect(statuses.every((s) => s === 2)).toBe(true);
    } finally {
      if (thrasher?.pid) {
        try {
          process.kill(thrasher.pid, 'SIGKILL');
        } catch {
          /* already gone */
        }
      }
      fs.rmSync(home, { recursive: true, force: true });
    }
  }, 120000);
});
