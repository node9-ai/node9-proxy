// DLP-2: a PII block row must never carry the PII.
//
// appendLocalAudit suppresses argsPreview for DLP rows (the matched secret is
// in the args). The PII gate emits checkedBy 'pii-block' /
// 'observe-mode-pii-would-block' with meta.piiPatterns, and the guard did not
// recognise either, so argsPreview WAS built and the shipper forwarded the raw
// SSN / card to the SaaS. Verified on a live row (doc/BUGS.md DLP-2).
//
// Two independent signals gate the suppression, combined by strictness: the
// checkedBy substring and the piiPatterns meta. P7 and P8 are synthetic rows
// that isolate each clause so both are mutation-killable on their own; no real
// caller produces them, which is exactly why they protect a future rename of
// the checkedBy value or a future caller that forgets the meta.
//
// fs.appendFileSync is spied (not mocked away) so we assert the exact JSON
// line without touching the real ~/.node9/audit.log. The SSN is assembled from
// split parts so neither this file nor the tool call that wrote it carries an
// SSN-shaped literal (node9's own realtime PII gate is active on this machine).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { appendLocalAudit, LOCAL_AUDIT_LOG } from '../audit/index';

const SSN = ['123', '45', '6789'].join('-');

let written: Array<{ path: string; line: string }> = [];

beforeEach(() => {
  written = [];
  vi.spyOn(fs, 'existsSync').mockReturnValue(true);
  vi.spyOn(fs, 'appendFileSync').mockImplementation((p, data) => {
    written.push({ path: String(p), line: String(data) });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

function lastRow(): Record<string, unknown> {
  const e = written.find((w) => w.path === LOCAL_AUDIT_LOG);
  expect(e, 'a row must have been written (instrument self-check)').toBeDefined();
  return JSON.parse(e!.line) as Record<string, unknown>;
}

function expectNoLeak(row: Record<string, unknown>) {
  expect(row.argsPreview).toBeUndefined();
  expect(typeof row.argsHash).toBe('string');
  expect(JSON.stringify(row)).not.toContain(SSN);
}

describe('appendLocalAudit — PII rows never carry the value (DLP-2)', () => {
  it('P1 pii-block: no argsPreview, hash only, SSN absent from the row', () => {
    appendLocalAudit(
      'Bash',
      { command: 'echo ' + SSN },
      'deny',
      'pii-block',
      { piiPatterns: 'SSN' },
      true
    );
    expectNoLeak(lastRow());
  });

  it('P2 observe-mode-pii-would-block: same guarantee', () => {
    appendLocalAudit(
      'Bash',
      { command: 'echo ' + SSN },
      'deny',
      'observe-mode-pii-would-block',
      { piiPatterns: 'SSN' },
      true
    );
    expectNoLeak(lastRow());
  });

  it('P3 dlp-block row is unchanged: still no argsPreview (regression guard)', () => {
    appendLocalAudit(
      'Bash',
      { command: 'export TOKEN=abc' },
      'deny',
      'dlp-block',
      { dlpPattern: 'GitHub Token', dlpSample: 'ghp_****' },
      true
    );
    const row = lastRow();
    expect(row.argsPreview).toBeUndefined();
    expect(typeof row.argsHash).toBe('string');
  });

  it('P4 known-true: an ordinary allow row STILL gets an argsPreview (no over-suppression)', () => {
    appendLocalAudit('Bash', { command: 'ls -la' }, 'allow', 'local-policy', {}, true);
    const row = lastRow();
    expect(typeof row.argsPreview).toBe('string');
    expect(typeof row.argsHash).toBe('string');
  });

  it('P7 checkedBy alone suppresses: pii-block with NO piiPatterns meta', () => {
    appendLocalAudit('Bash', { command: 'echo ' + SSN }, 'deny', 'pii-block', {}, true);
    expectNoLeak(lastRow());
  });

  it('P8 piiPatterns alone suppresses: neutral checkedBy WITH piiPatterns meta', () => {
    appendLocalAudit(
      'Bash',
      { command: 'echo ' + SSN },
      'deny',
      'local-policy',
      { piiPatterns: 'SSN' },
      true
    );
    expectNoLeak(lastRow());
  });
});
