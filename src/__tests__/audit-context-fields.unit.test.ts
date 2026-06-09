// Context fields on the local audit row (shipper-context-fields.md):
// workingDir / platform / shellType, so the SaaS event-detail Context block
// can show WHERE an action ran, not just its session.
//
// fs.appendFileSync is spied (not mocked away) so we assert the exact JSON
// line without touching the real ~/.node9/audit.log.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
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

function lastRow(): Record<string, unknown> {
  const e = written.find((w) => w.path === LOCAL_AUDIT_LOG);
  expect(e).toBeDefined();
  return JSON.parse(e!.line) as Record<string, unknown>;
}

describe('appendLocalAudit — context fields', () => {
  it('always records the platform', () => {
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
    expect(lastRow().platform).toBe(os.platform());
  });

  it('records workingDir when the caller provides it', () => {
    appendLocalAudit(
      'Bash',
      { command: 'ls' },
      'allow',
      'local-policy',
      { workingDir: '/home/nadav/node9' },
      true
    );
    expect(lastRow().workingDir).toBe('/home/nadav/node9');
  });

  it('omits workingDir when not provided (lean row)', () => {
    appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
    expect('workingDir' in lastRow()).toBe(false);
  });

  it('records shellType from $SHELL basename when set', () => {
    const prev = process.env.SHELL;
    process.env.SHELL = '/usr/bin/zsh';
    try {
      appendLocalAudit('Bash', { command: 'ls' }, 'allow', 'local-policy', {}, true);
      expect(lastRow().shellType).toBe('zsh');
    } finally {
      if (prev === undefined) delete process.env.SHELL;
      else process.env.SHELL = prev;
    }
  });
});
