// src/__tests__/scan-watermark-upload.spec.ts
//
// The watermark commit MUST follow an acknowledged upload on the totals
// path. This spec drives the REAL scan-watermark module and the REAL
// pushScanSnapshot against a tmp HOME, mocking only `https`, so every
// assertion reads the actual on-disk watermark and the actual POST body.
// That is the real gate; scan-watermark.spec.ts never POSTs and
// sync.test.ts mocks the watermark away, so neither could express these rows.
//
// The defect this pins: after an extractor-version reset the daemon
// re-scanned all history, SAVED the advanced offsets, then POSTed. A failed
// POST left the flag set but the offsets at EOF, so the retry sent only
// newly appended bytes as a full-row OVERWRITE. History was lost. The fix
// defers the save on the totals path until 2xx.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { CANONICAL_EXTRACTOR_VERSION } from '@node9/policy-engine';

const { mockHttpsRequest } = vi.hoisted(() => ({ mockHttpsRequest: vi.fn() }));
vi.mock('https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('https')>();
  return {
    ...actual,
    default: { ...actual, request: mockHttpsRequest },
    request: mockHttpsRequest,
  };
});

import { pushScanSnapshot } from '../daemon/sync.js';
import { tickScanWatcher, loadWatermark } from '../daemon/scan-watermark.js';

// ── tmp HOME (mirrors scan-watermark.spec.ts) ─────────────────────────────
let tmpHome: string;
let projectsDir: string;
let originalHome: string | undefined;
let originalUserProfile: string | undefined;

beforeEach(() => {
  originalHome = process.env.HOME;
  originalUserProfile = process.env.USERPROFILE;
  delete process.env.NODE9_SCAN_DISABLE;
  delete process.env.NODE9_SKIP_WATERMARK_RESET;
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-wm-upload-'));
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
  projectsDir = path.join(tmpHome, '.claude', 'projects');
  fs.mkdirSync(projectsDir, { recursive: true });
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  mockHttpsRequest.mockReset();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  if (originalUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = originalUserProfile;
  delete process.env.NODE9_SKIP_WATERMARK_RESET;
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

// ── fixtures ──────────────────────────────────────────────────────────────
const CREDS = { apiKey: 'test-key', apiUrl: 'https://api.example.com/policies/sync' };
const STALE_VERSION = 'canonical-v2';

function fakeGitHubToken(): string {
  const prefix = 'g' + 'h' + 'p' + '_';
  return prefix + 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOo0123456789'.slice(0, 36);
}
const T = () =>
  JSON.stringify({
    sessionId: 'conv-123',
    message: { content: 'token exposed: ' + fakeGitHubToken() },
  }) + '\n';
const P = () => JSON.stringify({ message: { content: 'just a normal message' } }) + '\n';

const sessionPath = (id = 'conv-123') => path.join(projectsDir, 'proj-abc', `${id}.jsonl`);
const wmPath = () => path.join(tmpHome, '.node9', 'scan-watermark.json');
const bytes = (s: string) => Buffer.byteLength(s, 'utf-8');

function writeSession(content: string, id = 'conv-123'): void {
  const p = sessionPath(id);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  const t = new Date('2026-01-01T00:00:00Z'); // older than createdAt: a KNOWN file, never "new"
  fs.utimesSync(p, t, t);
}
function appendSession(content: string, id = 'conv-123'): void {
  fs.appendFileSync(sessionPath(id), content);
}

/** Write a watermark keyed by the REAL session path so the known-file branch runs. */
function writeWatermark(opts: {
  extractorVersion: string;
  files: Record<string, number>;
  flag?: boolean;
}): void {
  fs.writeFileSync(
    wmPath(),
    JSON.stringify({
      schemaVersion: 2,
      extractorVersion: opts.extractorVersion,
      ...(opts.flag && { pendingResetUploadAs: 'totals' }),
      createdAt: '2026-04-15T10:00:00.000Z',
      files: Object.fromEntries(Object.entries(opts.files).map(([k, v]) => [k, { scannedTo: v }])),
    })
  );
}
const readDisk = () => fs.readFileSync(wmPath(), 'utf-8');
function readWm() {
  const s = loadWatermark();
  return {
    status: s.status,
    version: s.wm.extractorVersion,
    flag: s.wm.pendingResetUploadAs,
    files: s.wm.files,
  };
}

// ── https mock ────────────────────────────────────────────────────────────
type Mode = { status: number } | { fail: 'error' | 'timeout' };
type Body = Record<string, unknown>;
const captured: Body[] = [];

function installHttpsMock(mode: Mode): void {
  captured.length = 0;
  mockHttpsRequest.mockImplementation(((...args: unknown[]) => {
    const handlers: Record<string, (...a: unknown[]) => void> = {};
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const resCb = (args.find((a) => typeof a === 'function') as any) || (() => {});
    const req = {
      on: (ev: string, cb: (...a: unknown[]) => void) => {
        handlers[ev] = cb;
      },
      write: (body: string) => {
        captured.push(JSON.parse(body));
      },
      end: () => {
        setImmediate(() => {
          if ('fail' in mode) {
            handlers[mode.fail]?.();
            return;
          }
          const res = {
            statusCode: mode.status,
            resume: () => {},
            on: (ev: string, cb: (...a: unknown[]) => void) => {
              if (ev === 'end') setImmediate(() => cb());
            },
          };
          resCb(res);
        });
      },
      destroy: () => {},
    };
    return req;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  }) as any);
}
async function push(): Promise<void> {
  await pushScanSnapshot(CREDS);
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
}
const totalsOf = (b: Body) => b.sessionTotals as Array<Record<string, unknown>> | undefined;
const deltasOf = (b: Body) => b.sessionDeltas as Array<Record<string, unknown>> | undefined;
const calls = (rows: Array<Record<string, unknown>> | undefined) =>
  (rows ?? []).reduce((n, r) => n + Number(r.totalToolCalls ?? 0), 0);

// ── rows ──────────────────────────────────────────────────────────────────
describe('watermark upload ordering — the real gate', () => {
  it('R0b instrument: a 500 leaves posted=false (true before and after the fix)', async () => {
    writeSession(T() + T() + T());
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(T()) } });
    installHttpsMock({ status: 500 });
    await push();
    expect(captured).toHaveLength(1);
    expect(totalsOf(captured[0])).toBeDefined();
    // Whatever else happened, the flag was NOT cleared by a 500.
    expect(readWm().status === 'current' ? readWm().flag : 'totals').toBe('totals');
  });

  it('R1 normal deltas tick, 200: offsets advance, body is sessionDeltas', async () => {
    writeSession(P() + T());
    writeWatermark({
      extractorVersion: CANONICAL_EXTRACTOR_VERSION,
      files: { [sessionPath()]: bytes(P()) },
    });
    installHttpsMock({ status: 200 });
    await push();
    expect(captured).toHaveLength(1);
    expect(deltasOf(captured[0])).toBeDefined();
    expect(totalsOf(captured[0])).toBeUndefined();
    expect(calls(deltasOf(captured[0]))).toBe(1);
    expect(readWm().files[sessionPath()].scannedTo).toBe(bytes(P() + T()));
  });

  it('R2 reset then 200: full re-scan sent as totals, flag cleared, offsets committed', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    installHttpsMock({ status: 200 });
    await push();
    expect(captured).toHaveLength(1);
    expect(calls(totalsOf(captured[0]))).toBe(3);
    const wm = readWm();
    expect(wm.status).toBe('current');
    expect(wm.version).toBe(CANONICAL_EXTRACTOR_VERSION);
    expect(wm.flag).toBeUndefined();
    expect(wm.files[sessionPath()].scannedTo).toBe(bytes(content));
  });

  it('R3 CRITICAL — reset then 500: the disk is byte-identical, nothing committed', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    const before = readDisk();
    installHttpsMock({ status: 500 });
    await push();
    expect(captured).toHaveLength(1);
    expect(calls(totalsOf(captured[0]))).toBe(3);
    expect(readDisk()).toBe(before);
    expect(readWm().status).toBe('extractor-stale');
  });

  it('R4 retry after R3 with growth, 200: BE receives FULL history totals, not the fragment', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    installHttpsMock({ status: 500 });
    await push();
    appendSession(T());
    installHttpsMock({ status: 200 });
    await push();
    expect(captured).toHaveLength(1);
    expect(totalsOf(captured[0])).toBeDefined();
    // 4 lines total. Before the fix this was 1 (the appended line only).
    expect(calls(totalsOf(captured[0]))).toBe(4);
    expect(readWm().flag).toBeUndefined();
    expect(readWm().files[sessionPath()].scannedTo).toBe(bytes(content + T()));
  });

  it('R4b retry after R3 with NO growth, 200: retry is not gated on new bytes', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    installHttpsMock({ status: 500 });
    await push();
    installHttpsMock({ status: 200 });
    await push();
    // Before the fix: no POST at all (nothing grew), flag stuck forever.
    expect(captured).toHaveLength(1);
    expect(calls(totalsOf(captured[0]))).toBe(3);
    expect(readWm().flag).toBeUndefined();
  });

  it('R5 crash between scan and POST: the next full push still sends complete totals', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    const before = readDisk();
    const tick = await tickScanWatcher(); // scan happened, process "dies" here
    expect(tick.uploadAs).toBe('totals');
    expect(readDisk()).toBe(before); // nothing persisted by the scan alone
    installHttpsMock({ status: 200 });
    await push();
    expect(calls(totalsOf(captured[0]))).toBe(3);
    expect(readWm().flag).toBeUndefined();
  });

  it('R6 NODE9_SKIP_WATERMARK_RESET=1: no reset, offsets kept, deltas only', async () => {
    const content = T() + T() + T();
    writeSession(content);
    writeWatermark({
      extractorVersion: STALE_VERSION,
      files: { [sessionPath()]: bytes(T() + T()) },
    });
    process.env.NODE9_SKIP_WATERMARK_RESET = '1';
    installHttpsMock({ status: 200 });
    await push();
    expect(captured).toHaveLength(1);
    expect(deltasOf(captured[0])).toBeDefined();
    expect(calls(deltasOf(captured[0]))).toBe(1);
    expect(readWm().version).toBe(CANONICAL_EXTRACTOR_VERSION);
    expect(readWm().flag).toBeUndefined();
  });

  it('R6b the escape hatch still works AFTER a failed totals tick', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    installHttpsMock({ status: 500 });
    await push();
    // Disk still says the old version, so the ack path is still reachable.
    process.env.NODE9_SKIP_WATERMARK_RESET = '1';
    installHttpsMock({ status: 200 });
    await push();
    expect(captured).toHaveLength(0); // acknowledged, nothing grew, no totals ever sent
    expect(readWm().version).toBe(CANONICAL_EXTRACTOR_VERSION);
    expect(readWm().flag).toBeUndefined();
    expect(readWm().files[sessionPath()].scannedTo).toBe(bytes(content));
  });

  it('R7 two files, one grows: deltas are exactly the growth', async () => {
    writeSession(T() + T(), 'conv-123');
    writeSession(T(), 'conv-456');
    writeWatermark({
      extractorVersion: CANONICAL_EXTRACTOR_VERSION,
      files: { [sessionPath('conv-123')]: bytes(T() + T()), [sessionPath('conv-456')]: bytes(T()) },
    });
    appendSession(T(), 'conv-456');
    installHttpsMock({ status: 200 });
    await push();
    const rows = deltasOf(captured[0]) ?? [];
    expect(rows).toHaveLength(1);
    expect(calls(rows)).toBe(1);
  });

  it('R8 idempotency claim: a retried totals payload is never smaller than the first', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    installHttpsMock({ status: 500 });
    await push();
    const first = calls(totalsOf(captured[0]));
    appendSession(T());
    installHttpsMock({ status: 200 });
    await push();
    const second = calls(totalsOf(captured[0]));
    expect(second).toBeGreaterThanOrEqual(first); // before the fix: 1 < 3
  });

  it('R9 empty totals tick: flag clears without a POST', async () => {
    writeSession('');
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: 0 } });
    installHttpsMock({ status: 200 });
    await push();
    expect(captured).toHaveLength(0);
    expect(readWm().status).toBe('current');
    expect(readWm().flag).toBeUndefined();
  });

  it('R10 deltas semantics UNCHANGED: a failed delta is dropped, never retried', async () => {
    writeSession(P() + T());
    writeWatermark({
      extractorVersion: CANONICAL_EXTRACTOR_VERSION,
      files: { [sessionPath()]: bytes(P()) },
    });
    installHttpsMock({ status: 500 });
    await push();
    expect(readWm().files[sessionPath()].scannedTo).toBe(bytes(P() + T())); // advanced despite 500
    appendSession(T());
    installHttpsMock({ status: 200 });
    await push();
    expect(calls(deltasOf(captured[0]))).toBe(1); // only the new line, not a replay
  });

  it('R11 two overlapping totals pushes: both send full totals, final state consistent', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    installHttpsMock({ status: 200 });
    await Promise.all([pushScanSnapshot(CREDS), pushScanSnapshot(CREDS)]);
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    expect(captured).toHaveLength(2);
    for (const b of captured) expect(calls(totalsOf(b))).toBe(3);
    expect(readWm().status).toBe('current');
    expect(readWm().flag).toBeUndefined();
  });

  it('R13 timeout is a failure: identical to R3', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    const before = readDisk();
    installHttpsMock({ fail: 'timeout' });
    await push();
    expect(readDisk()).toBe(before);
    expect(readWm().status).toBe('extractor-stale');
  });

  it('R13b socket error is a failure: identical to R3', async () => {
    const content = T() + T() + P();
    writeSession(content);
    writeWatermark({ extractorVersion: STALE_VERSION, files: { [sessionPath()]: bytes(content) } });
    const before = readDisk();
    installHttpsMock({ fail: 'error' });
    await push();
    expect(readDisk()).toBe(before);
    expect(readWm().status).toBe('extractor-stale');
  });
});
