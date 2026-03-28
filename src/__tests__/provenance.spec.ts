import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'fs';
import { checkProvenance, _classifyPath } from '../utils/provenance.js';

// ── _classifyPath — pure location classification (no fs calls, no mocking) ──
// These tests call the pure function directly: no realpathSync, no statSync.

describe('_classifyPath — location classification', () => {
  it('classifies /usr/bin/curl as system', () => {
    expect(_classifyPath('/usr/bin/curl').trustLevel).toBe('system');
  });

  it('classifies /usr/sbin/iptables as system', () => {
    expect(_classifyPath('/usr/sbin/iptables').trustLevel).toBe('system');
  });

  it('classifies /bin/sh as system', () => {
    expect(_classifyPath('/bin/sh').trustLevel).toBe('system');
  });

  it('classifies /usr/local/bin/node as managed', () => {
    expect(_classifyPath('/usr/local/bin/node').trustLevel).toBe('managed');
  });

  it('classifies /tmp/curl as suspect', () => {
    const r = _classifyPath('/tmp/curl');
    expect(r.trustLevel).toBe('suspect');
    expect(r.reason).toMatch(/temp directory/i);
  });

  it('classifies /var/tmp/evil as suspect', () => {
    expect(_classifyPath('/var/tmp/evil').trustLevel).toBe('suspect');
  });

  it('classifies /dev/shm/backdoor as suspect', () => {
    expect(_classifyPath('/dev/shm/backdoor').trustLevel).toBe('suspect');
  });

  it('classifies binary inside project cwd as user', () => {
    const cwd = '/home/dev/myproject';
    const r = _classifyPath(`${cwd}/.bin/tool`, cwd);
    expect(r.trustLevel).toBe('user');
    expect(r.reason).toMatch(/project directory/i);
  });

  it('classifies /opt/custom/bin/mytool as unknown', () => {
    const r = _classifyPath('/opt/custom/bin/mytool');
    expect(r.trustLevel).toBe('unknown');
    expect(r.reason).toMatch(/unrecognized/i);
  });
});

// ── checkProvenance — world-writable check (needs statSync mock) ──────────────
// Only tests the world-writable code path, which requires a statSync mock.
// Uses /bin/sh — exists on all POSIX systems, so realpathSync succeeds without mocking.

describe('checkProvenance — world-writable check', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  // World-writable is a POSIX concept; /bin/sh doesn't exist on Windows.
  it.skipIf(process.platform === 'win32')('classifies a world-writable binary as suspect', () => {
    vi.spyOn(fs, 'statSync').mockReturnValue({ mode: 0o777 } as fs.Stats);
    // /bin/sh always exists on POSIX; realpathSync works on real fs without mocking
    const result = checkProvenance('/bin/sh');
    expect(result.trustLevel).toBe('suspect');
    expect(result.reason).toMatch(/world-writable/i);
  });
});

// ── checkProvenance — suspect path (no mocking needed) ───────────────────────
// Early suspect check runs before realpathSync, so no fs mocking required.

describe('checkProvenance — early suspect path detection', () => {
  it('classifies /tmp/curl as suspect without any mocking', () => {
    const result = checkProvenance('/tmp/curl');
    expect(result.trustLevel).toBe('suspect');
    expect(result.reason).toMatch(/temp directory/i);
  });

  it('classifies binary not found in PATH as unknown', () => {
    vi.spyOn(fs, 'accessSync').mockImplementation(() => {
      throw new Error('ENOENT');
    });
    const result = checkProvenance('notabinary');
    expect(result.trustLevel).toBe('unknown');
    expect(result.reason).toMatch(/not found/i);
    vi.restoreAllMocks();
  });
});
