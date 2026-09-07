// Pin rows for the two seams the canary feature will touch, GREEN on today's
// code before any change (canary-corpus.md section F). Two of them (F3b, F4)
// pin behaviour the canary commit is expected to flip; they exist so the flip
// is a visible red-to-green in that commit, not a silent change.
//
// The positive value is IMPORTED from the engine's checksum fixtures (split
// parts), never retyped: the repo holds no assembled credential.
import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { asm, WIF_VALID } from '../../packages/policy-engine/src/dlp/checksum.fixtures';
import { appendLocalAudit, LOCAL_AUDIT_LOG } from '../audit/index';
import { auditLocalAllow } from '../auth/cloud';

const wif = (): string => {
  const r = WIF_VALID.find((x) => x.id === 'wif-c-wiki');
  if (!r) throw new Error('fixture wif-c-wiki missing');
  return asm(r.parts);
};

// ── real-gate harness, copied from check.integration.test.ts ─────────────────
const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');
function makeTempHome(config: object): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-canary-pin-'));
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  fs.writeFileSync(path.join(tmpHome, '.node9', 'config.json'), JSON.stringify(config));
  return tmpHome;
}
function runCheck(payload: object, home: string) {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'check', JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(),
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      HOME: home,
      USERPROFILE: home,
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}
function lastAuditRow(home: string): Record<string, unknown> {
  const p = path.join(home, '.node9', 'audit.log');
  const lines = fs.readFileSync(p, 'utf-8').trim().split('\n').filter(Boolean);
  expect(lines.length, 'an audit row must exist (instrument self-check)').toBeGreaterThan(0);
  return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>;
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`dist/cli.js not found at ${CLI}; build first`);
});

describe('F1 / F1b: orchestrator regex-DLP block at the real gate', () => {
  let home: string;
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  it('F1 standard mode: deny, dlp-block row, sample masked, no argsPreview, value absent from the row', () => {
    home = makeTempHome({ settings: { mode: 'standard', autoStartDaemon: false } });
    const v = wif();
    const r = runCheck(
      {
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'echo ' + v },
        session_id: 'pin-f1',
        cwd: home,
      },
      home
    );
    const out = JSON.parse(r.stdout) as {
      hookSpecificOutput?: { permissionDecision?: string };
      reason?: string;
    };
    expect(out.hookSpecificOutput?.permissionDecision).toBe('deny');
    // The hook's outward reason is the agent-facing instruction block; the
    // internal 'DATA LOSS PREVENTION' string stays in the audit reason only.
    expect(out.reason ?? '').toMatch(/NODE9 SECURITY ALERT|DATA LOSS PREVENTION/);
    const row = lastAuditRow(home);
    expect(row.checkedBy).toBe('dlp-block');
    expect(row.dlpPattern).toBe('Bitcoin WIF Private Key');
    expect(String(row.dlpSample).startsWith(v.slice(0, 4))).toBe(true);
    expect(row.dlpSample).not.toBe(v);
    expect(typeof row.argsHash).toBe('string');
    expect(row.argsPreview).toBeUndefined();
    expect(JSON.stringify(row)).not.toContain(v);
  });

  it('F1b observe mode: exit 0, row says observe-mode-dlp-would-block', () => {
    home = makeTempHome({ settings: { mode: 'observe', autoStartDaemon: false } });
    const r = runCheck(
      {
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'echo ' + wif() },
        session_id: 'pin-f1b',
        cwd: home,
      },
      home
    );
    expect(r.status).toBe(0);
    expect(lastAuditRow(home).checkedBy).toBe('observe-mode-dlp-would-block');
  });
});

vi.mock('../ui/native', () => ({ sendDesktopNotification: vi.fn() }));

describe('F2: dlp-scanner per-pass dedup', () => {
  let tmpHome: string;
  let runDlpScan: () => void;
  let sendSpy: ReturnType<typeof vi.fn>;
  let projDir: string;
  let auditFile: string;
  beforeEach(async () => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-canary-pin-f2-'));
    vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    vi.resetModules();
    runDlpScan = (await import('../daemon/dlp-scanner.js')).runDlpScan;
    sendSpy = (await import('../ui/native.js')).sendDesktopNotification as ReturnType<typeof vi.fn>;
    sendSpy.mockClear();
    projDir = path.join(tmpHome, '.claude', 'projects', 'proj1');
    fs.mkdirSync(projDir, { recursive: true });
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    auditFile = path.join(tmpHome, '.node9', 'audit.log');
  });
  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    vi.restoreAllMocks();
  });
  it('same value x5 in one pass: 1 notification, 5 response-dlp rows naming the pattern', () => {
    const v = wif();
    const lines = [v, v, v, v, v]
      .map((t) =>
        JSON.stringify({
          type: 'assistant',
          timestamp: '2026-09-07T00:00:00Z',
          message: { content: [{ type: 'text', text: t }] },
        })
      )
      .join('\n');
    fs.writeFileSync(path.join(projDir, 'a.jsonl'), lines + '\n');
    runDlpScan();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    const rows = fs
      .readFileSync(auditFile, 'utf-8')
      .trim()
      .split('\n')
      .filter((l) => l.includes('"source":"response-dlp"'));
    expect(rows).toHaveLength(5);
    for (const l of rows)
      expect((JSON.parse(l) as { dlpPattern?: string }).dlpPattern).toBe('Bitcoin WIF Private Key');
  });
});

describe('F3: isDlpRow substring coverage (audit/index.ts)', () => {
  let written: Array<{ path: string; line: string }> = [];
  beforeEach(() => {
    written = [];
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'appendFileSync').mockImplementation((p, data) => {
      written.push({ path: String(p), line: String(data) });
    });
  });
  afterEach(() => vi.restoreAllMocks());
  const lastRow = () => {
    const e = written.find((w) => w.path === LOCAL_AUDIT_LOG);
    expect(e, 'row written').toBeDefined();
    return JSON.parse(e!.line) as Record<string, unknown>;
  };
  it('F3a: a checkedBy containing "dlp" (the chosen name dlp-canary-block) already suppresses argsPreview today', () => {
    appendLocalAudit('Bash', { command: 'x' }, 'deny', 'dlp-canary-block', {}, true);
    expect(lastRow().argsPreview).toBeUndefined();
  });
  it('F3b: the rejected name canary-block would NOT be covered (H1); pinned so the choice stays visible', () => {
    appendLocalAudit('Bash', { command: 'x' }, 'deny', 'canary-block', {}, true);
    expect(lastRow().argsPreview).toBeDefined();
  });
});

describe('F4: cloud shipper normalises an unknown checkedBy (auth/cloud.ts KNOWN_CHECKED_BY)', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('dlp-canary-block ships as "unknown" TODAY; the canary commit must flip this row', async () => {
    const fetchSpy = vi.fn(async () => ({ ok: true, status: 200 }) as Response);
    vi.stubGlobal('fetch', fetchSpy);
    await auditLocalAllow('Bash', { command: 'x' }, 'dlp-canary-block', {
      apiKey: 'k',
      apiUrl: 'http://127.0.0.1:0',
    });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const body = JSON.parse(
      String(
        (fetchSpy.mock.calls[0] as unknown[])[1] &&
          ((fetchSpy.mock.calls[0] as unknown[])[1] as { body: string }).body
      )
    ) as { checkedBy: string };
    expect(body.checkedBy).toBe('unknown');
  });
});
