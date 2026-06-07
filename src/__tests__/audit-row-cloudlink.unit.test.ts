// Writer-side contract for the cloudRequestId linkage (outbox shipper).
//
// A request that opened a pending cloud entry already has a BE-origin
// AuditLog row (written at /intercept time). The local row must carry the
// cloudRequestId so the shipper can hand the BE the linkage key — the BE
// then ENRICHES its origin row (sets clientEventId) instead of inserting a
// duplicate. Without this field, locally-resolved cloud-pending requests
// (e.g. native popup wins the race) would be counted twice.
//
// fs.appendFileSync is spied (not mocked away) so the test asserts the
// EXACT JSON line appendLocalAudit produces without touching the real
// ~/.node9/audit.log.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { appendLocalAudit, LOCAL_AUDIT_LOG } from '../audit/index';

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

function lastAuditRow(): Record<string, unknown> {
  const entry = written.find((w) => w.path === LOCAL_AUDIT_LOG);
  expect(entry).toBeDefined();
  return JSON.parse(entry!.line) as Record<string, unknown>;
}

describe('appendLocalAudit — cloudRequestId linkage', () => {
  it('writes cloudRequestId on the row when the decision had a pending cloud entry', () => {
    appendLocalAudit(
      'Bash',
      { command: 'git push' },
      'allow',
      'native',
      { agent: 'Claude Code', cloudRequestId: 'req-123' },
      true
    );
    const row = lastAuditRow();
    expect(row.cloudRequestId).toBe('req-123');
    expect(row.checkedBy).toBe('native');
    expect(typeof row.eid).toBe('string');
  });

  it('omits the field entirely when there was no cloud entry (steady-state rows stay lean)', () => {
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', undefined, true);
    const row = lastAuditRow();
    expect('cloudRequestId' in row).toBe(false);
  });
});
