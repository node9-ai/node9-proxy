// Tests for live forensic broadcast (PR-1 of option C):
//  - broadcastForensic: ScanFinding → ForensicEvent SSE payload + severity mapping
//  - tickForensicBroadcast: read-only JSONL scan with in-memory offsets that
//    never touches the persistent watermark used by the SaaS sync path.
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Type-only import — actual module loads after the homedir spy is installed.
import type { ForensicEvent } from '../daemon/state.js';

function parseSseFrame(frame: string): { event: string; data: ForensicEvent } {
  // SSE frame shape: "event: <name>\ndata: <json>\n\n"
  const eventMatch = frame.match(/^event: (.+?)\n/);
  const dataMatch = frame.match(/\ndata: (.+?)\n\n/);
  if (!eventMatch || !dataMatch) throw new Error('malformed SSE frame: ' + frame);
  return { event: eventMatch[1], data: JSON.parse(dataMatch[1]) as ForensicEvent };
}

describe('broadcastForensic', () => {
  let written: string[];
  let stateModule: typeof import('../daemon/state.js');
  let tmpHome: string;
  let homeSpy: ReturnType<typeof vi.spyOn>;

  // Cold dynamic import of the daemon module tree can exceed the default 10s
  // hook timeout under parallel CI load — load it ONCE here with headroom, not
  // per-test, so the suite stops flaking on `beforeEach` timeouts.
  beforeAll(async () => {
    stateModule = await import('../daemon/state.js');
  }, 30_000);

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-state-'));
    homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);

    written = [];
    const mockClient = {
      res: {
        write: (s: string) => {
          written.push(s);
          return true;
        },
      },
      capabilities: [],
    };
    stateModule.sseClients.add(mockClient as never);
  });

  afterEach(() => {
    stateModule.sseClients.clear();
    homeSpy.mockRestore();
    // Windows: createReadStream inside tickForensicBroadcast briefly pins
    // a child file past test completion, so an immediate recursive rm can
    // hit ENOTEMPTY. maxRetries + retryDelay (Node 14.14+) retries on the
    // documented set (EBUSY, EMFILE, ENFILE, ENOTEMPTY, EPERM) with linear
    // backoff. POSIX runs aren't affected — happy path is unchanged.
    fs.rmSync(tmpHome, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it('emits a forensic SSE event with correct shape', () => {
    stateModule.broadcastForensic({
      sessionId: 'sess-A',
      type: 'pii',
      patternName: 'email',
      lineIndex: 7,
    });

    expect(written).toHaveLength(1);
    const { event, data } = parseSseFrame(written[0]);
    expect(event).toBe('forensic');
    expect(data.type).toBe('forensic');
    expect(data.sessionId).toBe('sess-A');
    expect(data.category).toBe('pii');
    expect(data.patternName).toBe('email');
    expect(data.severity).toBe('warning');
    expect(typeof data.id).toBe('string');
    expect(data.id.startsWith('fnd_')).toBe(true);
    expect(typeof data.ts).toBe('number');
  });

  it('marks privilege-escalation as critical severity', () => {
    stateModule.broadcastForensic({
      sessionId: 's1',
      type: 'privilege-escalation',
      lineIndex: 1,
    });
    expect(parseSseFrame(written[0]).data.severity).toBe('critical');
  });

  it('marks destructive-op as critical severity', () => {
    stateModule.broadcastForensic({
      sessionId: 's1',
      type: 'destructive-op',
      lineIndex: 1,
    });
    expect(parseSseFrame(written[0]).data.severity).toBe('critical');
  });

  it('marks eval-of-remote as critical severity', () => {
    stateModule.broadcastForensic({
      sessionId: 's1',
      type: 'eval-of-remote',
      lineIndex: 1,
    });
    expect(parseSseFrame(written[0]).data.severity).toBe('critical');
  });

  it('marks non-critical categories as warning', () => {
    const cases: Array<import('@node9/policy-engine').ScanFinding['type']> = [
      'pii',
      'sensitive-file-read',
      'pipe-to-shell',
      'long-output-redacted',
      'dlp',
      'network-exfil',
      'loop',
    ];
    for (const type of cases) {
      written.length = 0;
      stateModule.broadcastForensic({ sessionId: 's1', type, lineIndex: 1 });
      expect(parseSseFrame(written[0]).data.severity, `severity for ${type}`).toBe('warning');
    }
  });

  it('omits patternName field when finding has no pattern', () => {
    stateModule.broadcastForensic({
      sessionId: 's1',
      type: 'privilege-escalation',
      lineIndex: 1,
    });
    const data = parseSseFrame(written[0]).data;
    expect(data.patternName).toBeUndefined();
    // Verify no leak of lineIndex into the SSE payload (privacy invariant).
    expect((data as unknown as Record<string, unknown>).lineIndex).toBeUndefined();
  });

  it('broadcasts to every connected SSE client', () => {
    const writtenB: string[] = [];
    stateModule.sseClients.add({
      res: { write: (s: string) => writtenB.push(s) },
      capabilities: [],
    } as never);
    stateModule.broadcastForensic({
      sessionId: 's1',
      type: 'pii',
      lineIndex: 1,
    });
    expect(written).toHaveLength(1);
    expect(writtenB).toHaveLength(1);
  });
});

describe('tickForensicBroadcast', () => {
  let tmpHome: string;
  let homeSpy: ReturnType<typeof vi.spyOn>;
  let scanWatermark: typeof import('../daemon/scan-watermark.js');
  let projectDir: string;

  // Hoisted out of beforeEach: the cold module-tree import is the slow part and
  // doesn't need to run per-test — load once with headroom so a CI-load spike
  // can't blow the 10s hook timeout.
  beforeAll(async () => {
    scanWatermark = await import('../daemon/scan-watermark.js');
  }, 30_000);

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'fb-tick-'));
    homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    projectDir = path.join(tmpHome, '.claude', 'projects', 'proj1');
    fs.mkdirSync(projectDir, { recursive: true });
  });

  afterEach(() => {
    homeSpy.mockRestore();
    // Windows: createReadStream inside tickForensicBroadcast briefly pins
    // a child file past test completion, so an immediate recursive rm can
    // hit ENOTEMPTY. maxRetries + retryDelay (Node 14.14+) retries on the
    // documented set (EBUSY, EMFILE, ENFILE, ENOTEMPTY, EPERM) with linear
    // backoff. POSIX runs aren't affected — happy path is unchanged.
    fs.rmSync(tmpHome, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it('returns empty when no Claude projects directory exists', async () => {
    fs.rmSync(path.join(tmpHome, '.claude'), { recursive: true });
    const offsets = new Map<string, number>();
    const findings = await scanWatermark.tickForensicBroadcast(offsets);
    expect(findings).toEqual([]);
  });

  it('initializes offset to current EOF on first sight; returns no historical findings', async () => {
    const file = path.join(projectDir, 'session-A.jsonl');
    // Pre-existing line that *would* match an extractor, but it predates our
    // first tick so it must NOT be broadcast (the dashboard's mount-time scan
    // covers history; the broadcast channel is for new-content only).
    const historical = JSON.stringify({
      message: { content: 'note: my email is user@example.com please contact me' },
    });
    fs.writeFileSync(file, historical + '\n');

    const offsets = new Map<string, number>();
    const findings = await scanWatermark.tickForensicBroadcast(offsets);

    expect(findings).toEqual([]);
    expect(offsets.get(file)).toBe(fs.statSync(file).size);
  });

  it('detects findings in lines appended after the first tick', async () => {
    const file = path.join(projectDir, 'session-B.jsonl');
    fs.writeFileSync(
      file,
      JSON.stringify({ message: { content: 'baseline neutral content' } }) + '\n'
    );

    const offsets = new Map<string, number>();
    await scanWatermark.tickForensicBroadcast(offsets); // first tick — offset := EOF

    // Append a new line that matches the PII extractor.
    fs.appendFileSync(
      file,
      JSON.stringify({ message: { content: 'new line with email leak@corp.example' } }) + '\n'
    );

    const findings = await scanWatermark.tickForensicBroadcast(offsets);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.type === 'pii')).toBe(true);
    expect(findings.every((f) => f.sessionId === 'session-B')).toBe(true);
  });

  it('does not touch the persistent watermark file', async () => {
    const file = path.join(projectDir, 'session-C.jsonl');
    fs.writeFileSync(file, JSON.stringify({ message: { content: 'baseline' } }) + '\n');

    const watermarkFile = path.join(tmpHome, '.node9', 'scan-watermark.json');
    const offsets = new Map<string, number>();
    await scanWatermark.tickForensicBroadcast(offsets);

    // Append + tick again
    fs.appendFileSync(
      file,
      JSON.stringify({ message: { content: 'pii email user@x.example' } }) + '\n'
    );
    await scanWatermark.tickForensicBroadcast(offsets);

    // Local-broadcast path must never write the persistent watermark — the
    // SaaS sync path owns that file.
    expect(fs.existsSync(watermarkFile)).toBe(false);
  });
});
