/**
 * Integration test (phase 4): the inline-ask OUTCOME loop end-to-end.
 *
 *   Pre  — `node9 check --ask` on a review verdict → emits ask AND records a
 *          pending-review marker in ~/.node9/pending-reviews.json.
 *   Post — `node9 log` for the matching executed tool → resolves the marker and
 *          tags the audit row source:'inline-review-approved' (= user approved).
 *
 * Isolated per test via HOME=tmpHome (the store + audit.log live under tmpHome/.node9).
 * Requires `npm run build` (spawns dist/cli.js).
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let tmpHome: string;

function run(
  cmd: 'check' | 'log',
  args: string[],
  payload: object
): { status: number | null; stdout: string } {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, cmd, ...args, JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: tmpHome,
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      HOME: tmpHome,
      USERPROFILE: tmpHome,
    },
  });
  return { status: r.status, stdout: r.stdout ?? '' };
}

const pendingStore = () => path.join(tmpHome, '.node9', 'pending-reviews.json');
const auditLog = () => path.join(tmpHome, '.node9', 'audit.log');
const readJson = (p: string) => JSON.parse(fs.readFileSync(p, 'utf-8'));
const lastAuditRow = () => {
  const lines = fs.readFileSync(auditLog(), 'utf-8').trim().split('\n').filter(Boolean);
  return JSON.parse(lines[lines.length - 1]);
};

const claudePre = {
  hook_event_name: 'PreToolUse',
  tool_name: 'bash',
  tool_input: { command: 'git push origin main' },
  session_id: 's1',
  tool_use_id: 'toolu_phase4',
};
const claudePost = {
  hook_event_name: 'PostToolUse',
  tool_name: 'bash',
  tool_input: { command: 'git push origin main' },
  session_id: 's1',
  tool_use_id: 'toolu_phase4',
};

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build` first');
});
beforeEach(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-p4-'));
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(tmpHome, '.node9', 'config.json'),
    JSON.stringify({
      version: '1.0',
      settings: { mode: 'standard', autoStartDaemon: false, approvalTimeoutMs: 0 },
      policy: {
        smartRules: [
          {
            name: 'review-git-push',
            tool: 'bash',
            conditions: [{ field: 'command', op: 'matches', value: '\\bgit\\b.*\\bpush\\b' }],
            conditionMode: 'all',
            verdict: 'review',
            reason: 'git push sends changes to a shared remote',
          },
        ],
      },
    })
  );
});
afterEach(() => {
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('inline-ask outcome capture (phase 4)', () => {
  it('check --ask on a review records a pending marker keyed by tool_use_id', () => {
    const r = run('check', ['--ask'], claudePre);
    expect(r.status).toBe(0); // ask emitted
    const store = readJson(pendingStore());
    expect(store.entries).toHaveLength(1);
    expect(store.entries[0].key).toBe('tuid:toolu_phase4');
  });

  it('matching PostToolUse resolves the marker → audit row source=inline-review-approved', () => {
    run('check', ['--ask'], claudePre); // writes pending
    const post = run('log', [], claudePost); // resolves it
    expect(post.status).toBe(0);
    expect(lastAuditRow().source).toBe('inline-review-approved');
    // Marker consumed.
    expect(readJson(pendingStore()).entries).toHaveLength(0);
  });

  it('non-matching PostToolUse is a normal post-hook row (no false resolve)', () => {
    run('check', ['--ask'], claudePre); // pending key tuid:toolu_phase4
    const other = { ...claudePost, tool_use_id: 'toolu_other' };
    run('log', [], other);
    expect(lastAuditRow().source).toBe('post-hook');
    // Original marker untouched.
    expect(readJson(pendingStore()).entries).toHaveLength(1);
  });
});
