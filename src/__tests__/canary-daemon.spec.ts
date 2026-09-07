// Canary corpus E7 and E16: the transcript daemon (src/daemon/dlp-scanner.ts).
// Same harness as dlp-scanner-noise.spec.ts: spied homedir, resetModules, dynamic
// imports, a real plant in the tmp HOME, values read back from the registry.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { genAwsId } from '../../packages/policy-engine/src/dlp/canary.fixtures';

vi.mock('../ui/native', () => ({ sendDesktopNotification: vi.fn() }));

type Rec = {
  id: string;
  kind: string;
  field: string;
  path: string;
  value: string;
  retiredAt?: string;
};

describe('daemon: decoy credentials in Claude responses', () => {
  let tmpHome: string;
  let runDlpScan: () => void;
  let sendSpy: ReturnType<typeof vi.fn>;
  let plantKind: (k: 'aws-profile', home?: string) => unknown;
  let rotateKind: (k: 'aws-profile', home?: string) => unknown;
  let projDir: string;
  let auditFile: string;

  const records = (): Rec[] =>
    (
      JSON.parse(fs.readFileSync(path.join(tmpHome, '.node9', 'canaries.json'), 'utf-8')) as {
        records: Rec[];
      }
    ).records;
  const liveAwsId = () =>
    records().find(
      (r) => r.kind === 'aws-profile' && r.field === 'aws_access_key_id' && !r.retiredAt
    )!;
  const writeTranscript = (file: string, texts: string[], append = false) => {
    const lines =
      texts
        .map((t) =>
          JSON.stringify({
            type: 'assistant',
            timestamp: '2026-09-07T00:00:00Z',
            message: { content: [{ type: 'text', text: t }] },
          })
        )
        .join('\n') + '\n';
    const p = path.join(projDir, file);
    if (append) fs.appendFileSync(p, lines);
    else fs.writeFileSync(p, lines);
  };
  const rows = () =>
    (fs.existsSync(auditFile) ? fs.readFileSync(auditFile, 'utf-8').trim().split('\n') : [])
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, unknown>);

  beforeEach(async () => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-canary-daemon-'));
    vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    vi.resetModules();
    runDlpScan = (await import('../daemon/dlp-scanner.js')).runDlpScan;
    sendSpy = (await import('../ui/native.js')).sendDesktopNotification as ReturnType<typeof vi.fn>;
    const plant = await import('../canary/plant.js');
    plantKind = plant.plantKind;
    rotateKind = plant.rotateKind;
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

  it('E7 the decoy in five assistant blocks: one notification naming the plant path (never the value), five canary-response rows', () => {
    plantKind('aws-profile', tmpHome);
    const rec = liveAwsId();
    writeTranscript(
      'a.jsonl',
      [rec.value, rec.value, rec.value, rec.value, rec.value].map((v) => 'here is ' + v)
    );
    runDlpScan();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    const body = String((sendSpy.mock.calls[0] as unknown[]).join(' '));
    expect(body).toContain(rec.path);
    expect(body.includes(rec.value)).toBe(false);
    const canaryRows = rows().filter((r) => r.checkedBy === 'dlp-canary-response');
    expect(canaryRows).toHaveLength(5);
    for (const r of canaryRows) {
      expect(r.source).toBe('response-dlp');
      expect(r.canaryId).toBe(rec.id);
      expect(typeof r.canaryHash).toBe('string');
      expect(r.canaryPath).toBe(rec.path);
      expect(JSON.stringify(r).includes(rec.value)).toBe(false);
    }
    // The shape path fired too (an aws id) and its rows still carry source: response-dlp.
    expect(rows().filter((r) => r.source === 'response-dlp').length).toBeGreaterThanOrEqual(5);
  });

  it('E7b two different decoys in one pass: still one notification, and it says how many more', () => {
    plantKind('aws-profile', tmpHome);
    const a = liveAwsId();
    const secret = records().find(
      (r) => r.kind === 'aws-profile' && r.field === 'aws_secret_access_key'
    )!;
    writeTranscript('a.jsonl', ['x ' + a.value, 'y ' + secret.value]);
    runDlpScan();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(String((sendSpy.mock.calls[0] as unknown[]).join(' '))).toMatch(/\+1 more/);
  });

  it('E16 the registry is re-read per pass: after a rotate without re-import, the new value fires on the next pass', () => {
    plantKind('aws-profile', tmpHome);
    const v1 = liveAwsId();
    writeTranscript('a.jsonl', ['first ' + v1.value]);
    runDlpScan();
    expect(
      rows().filter((r) => r.checkedBy === 'dlp-canary-response' && r.canaryId === v1.id)
    ).toHaveLength(1);
    rotateKind('aws-profile', tmpHome);
    const v2 = liveAwsId();
    expect(v2.id).not.toBe(v1.id);
    writeTranscript('a.jsonl', ['second ' + v2.value], true);
    sendSpy.mockClear();
    runDlpScan();
    const second = rows().filter(
      (r) => r.checkedBy === 'dlp-canary-response' && r.canaryId === v2.id
    );
    expect(second).toHaveLength(1);
    expect(sendSpy).toHaveBeenCalledTimes(1);
  });

  it('known-true separation: an unregistered decoy-shaped value produces a regex row and no canary row', () => {
    plantKind('aws-profile', tmpHome);
    const stranger = genAwsId('canary-corpus-v1:daemon-stranger');
    expect(records().some((r) => r.value === stranger)).toBe(false);
    writeTranscript('a.jsonl', ['stranger ' + stranger]);
    runDlpScan();
    expect(rows().filter((r) => r.checkedBy === 'dlp-canary-response')).toHaveLength(0);
    expect(rows().filter((r) => r.source === 'response-dlp')).toHaveLength(1);
  });
});
