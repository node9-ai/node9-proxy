// P1 DLP noise fix — a single legitimate session must not fire N popups for the
// same secret. Dedup by patternName+redactedSample (persisted seen-set), and
// aggregate a scan pass into ONE notification while keeping all audit rows.
// The scanner resolves INDEX_FILE/PROJECTS_DIR/AUDIT_LOG_FILE from os.homedir()
// at import, so spy homedir + resetModules + dynamic import per test.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../ui/native', () => ({
  sendDesktopNotification: vi.fn(),
  askNativePopup: vi.fn(),
}));

const BEARER = 'Bearer abcdefghij0123456789klmnopqrstuvwx';
const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dozjgNryP4J3jVmNHl0w5NabcdEfghIJKL';

describe('dlp-scanner noise fix', () => {
  let tmpHome: string;
  let runDlpScan: () => void;
  let sendSpy: ReturnType<typeof vi.fn>;
  let projDir: string;
  let auditFile: string;
  let indexFile: string;

  beforeEach(async () => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-dlpscan-'));
    vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    vi.resetModules();
    runDlpScan = (await import('../daemon/dlp-scanner.js')).runDlpScan;
    sendSpy = (await import('../ui/native.js')).sendDesktopNotification as ReturnType<typeof vi.fn>;
    sendSpy.mockClear();
    projDir = path.join(tmpHome, '.claude', 'projects', 'proj1');
    fs.mkdirSync(projDir, { recursive: true });
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    auditFile = path.join(tmpHome, '.node9', 'audit.log');
    indexFile = path.join(tmpHome, '.node9', 'dlp-index.json');
  });

  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  const writeTranscript = (file: string, texts: string[], append = false) => {
    const lines =
      texts
        .map((t) =>
          JSON.stringify({
            type: 'assistant',
            timestamp: '2026-07-02T00:00:00Z',
            message: { content: [{ type: 'text', text: t }] },
          })
        )
        .join('\n') + '\n';
    const p = path.join(projDir, file);
    if (append) fs.appendFileSync(p, lines);
    else fs.writeFileSync(p, lines);
  };
  const dlpAuditRows = () =>
    (fs.existsSync(auditFile) ? fs.readFileSync(auditFile, 'utf-8').trim().split('\n') : [])
      .filter(Boolean)
      .filter((l) => l.includes('"source":"response-dlp"'));

  it('same secret ×5 in one pass → 1 notification, 5 audit rows', () => {
    writeTranscript('a.jsonl', [JWT, JWT, JWT, JWT, JWT]);
    runDlpScan();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(dlpAuditRows()).toHaveLength(5);
  });

  it('a re-leak in a LATER pass RE-NOTIFIES (dedup is per-pass, NOT permanent)', () => {
    // Security: persisting the seen-set would suppress an ongoing re-leak forever.
    // A new leak event (new bytes in a later pass) must alert again.
    writeTranscript('a.jsonl', [JWT]);
    runDlpScan();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    sendSpy.mockClear();
    writeTranscript('a.jsonl', [JWT], true); // append: the secret leaks again
    runDlpScan();
    expect(sendSpy).toHaveBeenCalledTimes(1); // re-alerted, not silently suppressed
    expect(dlpAuditRows()).toHaveLength(2);
  });

  it('two DIFFERENT secrets in one pass → 1 SUMMARY notification, 2 audit rows', () => {
    writeTranscript('a.jsonl', [JWT, BEARER]);
    runDlpScan();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(String(sendSpy.mock.calls[0][1])).toMatch(/2 new secrets/);
    expect(dlpAuditRows()).toHaveLength(2);
  });

  it('no NEW bytes since last pass → no popup (offset skip)', () => {
    writeTranscript('a.jsonl', [JWT]);
    runDlpScan();
    sendSpy.mockClear();
    runDlpScan(); // same file, no appended bytes → nothing to scan
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  it('a legacy flat-map index loads without crashing (index stays a flat map)', () => {
    fs.writeFileSync(indexFile, JSON.stringify({ '/old/path.jsonl': 999 }));
    writeTranscript('a.jsonl', [JWT]);
    expect(() => runDlpScan()).not.toThrow();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    const idx = JSON.parse(fs.readFileSync(indexFile, 'utf-8'));
    expect(idx).not.toHaveProperty('seen'); // no persisted seen-set anymore
    expect(typeof idx[path.join(projDir, 'a.jsonl')]).toBe('number'); // flat offset
  });
});
