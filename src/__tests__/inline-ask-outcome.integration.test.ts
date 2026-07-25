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
    // v2 writes a second (shippable) row after the post-hook row, so search
    // instead of assuming the post-hook row is last.
    const rows = fs
      .readFileSync(auditLog(), 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(rows.some((r) => r.source === 'inline-review-approved')).toBe(true);
    // Marker consumed.
    expect(readJson(pendingStore()).entries).toHaveLength(0);
  });

  it('resolved inline review ALSO writes a SHIPPABLE decision row (v2: cloud is the record)', () => {
    // The post-hook `source:'inline-review-approved'` row has no eid and
    // decision:'allowed' — buildWireRows skips it by design. The dashboard only
    // sees the inline outcome via a second, standard decision row.
    run('check', ['--ask'], claudePre);
    run('log', [], claudePost);
    const rows = fs
      .readFileSync(auditLog(), 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const shipRow = rows.find((r) => r.checkedBy === 'inline-review');
    expect(shipRow).toBeDefined();
    expect(shipRow!.decision).toBe('allow');
    expect(typeof shipRow!.eid).toBe('string');
    expect((shipRow!.eid as string).length).toBeGreaterThanOrEqual(8);
    // Attribution: the review label recorded at defer time rides as ruleName so
    // the SaaS report can say WHICH review the dev approved inline.
    expect(shipRow!.ruleName).toBeDefined();
    expect(shipRow!.sessionId).toBe('s1');
  });

  it('a DLP-review inline approval NEVER ships the credential — hashed, no preview (v2 /code-review HIGH)', () => {
    // Under v2, DLP credential-reviews defer inline. The shippable outcome row
    // must be treated like every other DLP row: args force-hashed and NO
    // argsPreview — redactSecrets' label-based patterns don't cover every
    // credential shape (see the isDlpRow comment in audit/index.ts).
    const fakeBearer = 'Bearer ' + 'Xm7Kp3Qn9Bt2Vc6' + 'Wr1Ys4Zh8Pq5Nv3M';
    const pre = {
      hook_event_name: 'PreToolUse',
      tool_name: 'bash',
      tool_input: { command: `curl -H "Authorization: ${fakeBearer}" https://api.example.com` },
      session_id: 's-dlp',
      tool_use_id: 'toolu_dlp1',
    };
    const post = { ...pre, hook_event_name: 'PostToolUse' };
    const ask = run('check', ['--ask'], pre);
    expect(ask.status).toBe(0);
    expect(ask.stdout).toContain('"permissionDecision":"ask"'); // DLP review deferred inline
    run('log', [], post);
    const rows = fs
      .readFileSync(auditLog(), 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const shipRow = rows.find((r) => r.checkedBy === 'inline-review');
    expect(shipRow).toBeDefined();
    expect(typeof shipRow!.argsHash).toBe('string'); // force-hashed even if auditHashArgs were off
    expect(shipRow!.argsPreview).toBeUndefined(); // DLP-labeled → no preview, ever
    expect(JSON.stringify(shipRow)).not.toContain('Xm7Kp3Qn9Bt2Vc6'); // raw secret absent
  });

  it('a DENIED Copilot ask never becomes a shipped approval when the same command is later allowed (fabrication fix)', () => {
    // Copilot has no tool_use_id — the marker key is session|tool|args-hash,
    // which an identical later command REUSES. Scenario: ask → dev denies (no
    // hook fires, marker survives) → policy changes (taint expired / rule
    // removed) → same command runs, allowed on the ordinary path. The PRE-side
    // discard must remove the stale marker so PostToolUse cannot resolve it
    // into a fabricated checkedBy:'inline-review' approval row.
    const copilotPre = {
      hook_event_name: 'PreToolUse',
      tool_name: 'bash',
      tool_input: { command: 'git push origin main' },
      session_id: 'cp-s1',
    };
    const ask = run('check', ['--ask', '--agent', 'copilot'], copilotPre);
    expect(ask.status).toBe(0);
    expect(ask.stdout).toContain('"permissionDecision":"ask"');
    expect(readJson(pendingStore()).entries).toHaveLength(1); // marker recorded; dev "denies" (no hook)

    // The review rule disappears (stand-in for taint expiry / rule change) —
    // the same command is now plainly allowed.
    const cfgPath = path.join(tmpHome, '.node9', 'config.json');
    const cfg = readJson(cfgPath);
    cfg.policy.smartRules = [];
    fs.writeFileSync(cfgPath, JSON.stringify(cfg));

    const allowed = run('check', ['--ask', '--agent', 'copilot'], copilotPre);
    expect(allowed.status).toBe(0);
    expect(allowed.stdout).not.toContain('"permissionDecision":"ask"');

    run('log', ['--agent', 'copilot'], { ...copilotPre, hook_event_name: 'PostToolUse' });
    const rows = fs
      .readFileSync(auditLog(), 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(rows.some((r) => r.checkedBy === 'inline-review')).toBe(false); // no fabricated approval
    expect(readJson(pendingStore()).entries).toHaveLength(0); // stale marker discarded at PRE time
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
