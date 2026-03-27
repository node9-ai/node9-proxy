// src/__tests__/auth-state.test.ts
// Unit tests for src/auth/state.ts — pause sessions, trust sessions.
//
// NOTE: auth/state.ts computes PAUSED_FILE and TRUST_FILE at module-load time
// using os.homedir(), so tests must derive those same paths rather than using
// a mocked homedir. All filesystem side-effects are intercepted via spies.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// ── Filesystem spies (must be set up before importing auth/state) ─────────────
const existsSpy = vi.spyOn(fs, 'existsSync');
const readSpy = vi.spyOn(fs, 'readFileSync');
const writeSpy = vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
const renameSpy = vi.spyOn(fs, 'renameSync').mockImplementation(() => undefined);
const unlinkSpy = vi.spyOn(fs, 'unlinkSync').mockImplementation(() => undefined);

// Import after mocks are in place so no real I/O happens on module init.
import {
  checkPause,
  pauseNode9,
  resumeNode9,
  getActiveTrustSession,
  writeTrustSession,
} from '../auth/state.js';

// Derive paths the same way the module does — avoids a brittle hardcoded constant.
const HOME = os.homedir();
const PAUSED_FILE = path.join(HOME, '.node9', 'PAUSED');
const TRUST_FILE = path.join(HOME, '.node9', 'trust.json');

beforeEach(() => {
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  writeSpy.mockClear();
  renameSpy.mockClear();
  unlinkSpy.mockClear();
});

afterEach(() => {
  vi.clearAllMocks();
});

// ── checkPause ────────────────────────────────────────────────────────────────

describe('checkPause', () => {
  it('returns paused:false when PAUSED file does not exist', () => {
    expect(checkPause()).toEqual({ paused: false });
  });

  it('returns paused:true with expiry and duration when file has a future expiry', () => {
    const expiry = Date.now() + 60_000;
    existsSpy.mockImplementation((p) => String(p) === PAUSED_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === PAUSED_FILE ? JSON.stringify({ expiry, duration: '1m' }) : ''
    );
    expect(checkPause()).toEqual({ paused: true, expiresAt: expiry, duration: '1m' });
  });

  it('returns paused:true when expiry is 0 (indefinite pause)', () => {
    existsSpy.mockImplementation((p) => String(p) === PAUSED_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === PAUSED_FILE ? JSON.stringify({ expiry: 0, duration: 'indefinite' }) : ''
    );
    // expiry 0 means "never expires" — the `expiry > 0` guard skips the expiry check
    expect(checkPause()).toEqual({ paused: true, expiresAt: 0, duration: 'indefinite' });
  });

  it('auto-deletes PAUSED file and returns paused:false when expiry has passed', () => {
    const expiry = Date.now() - 1000; // in the past
    existsSpy.mockImplementation((p) => String(p) === PAUSED_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === PAUSED_FILE ? JSON.stringify({ expiry, duration: '1m' }) : ''
    );
    expect(checkPause()).toEqual({ paused: false });
    expect(unlinkSpy).toHaveBeenCalledWith(PAUSED_FILE);
  });

  it('returns paused:false when PAUSED file contains malformed JSON', () => {
    existsSpy.mockImplementation((p) => String(p) === PAUSED_FILE);
    readSpy.mockImplementation((p) => (String(p) === PAUSED_FILE ? 'not-json{{{' : ''));
    expect(checkPause()).toEqual({ paused: false });
  });
});

// ── pauseNode9 ────────────────────────────────────────────────────────────────

describe('pauseNode9', () => {
  it('writes PAUSED file with correct duration and a future expiry', () => {
    const before = Date.now();
    pauseNode9(30_000, '30s');

    // atomicWriteSync: writeFileSync(tmp) then renameSync(tmp → dest)
    expect(writeSpy).toHaveBeenCalled();
    const written = JSON.parse(writeSpy.mock.calls[0][1] as string) as {
      expiry: number;
      duration: string;
    };
    expect(written.duration).toBe('30s');
    expect(written.expiry).toBeGreaterThanOrEqual(before + 30_000);

    expect(renameSpy).toHaveBeenCalled();
    const dest = renameSpy.mock.calls[0][1] as string;
    expect(dest).toBe(PAUSED_FILE);
  });
});

// ── resumeNode9 ───────────────────────────────────────────────────────────────

describe('resumeNode9', () => {
  it('deletes PAUSED file when it exists', () => {
    existsSpy.mockImplementation((p) => String(p) === PAUSED_FILE);
    resumeNode9();
    expect(unlinkSpy).toHaveBeenCalledWith(PAUSED_FILE);
  });

  it('is a no-op when PAUSED file does not exist', () => {
    resumeNode9();
    expect(unlinkSpy).not.toHaveBeenCalled();
  });
});

// ── getActiveTrustSession ─────────────────────────────────────────────────────

describe('getActiveTrustSession', () => {
  it('returns false when trust file does not exist', () => {
    expect(getActiveTrustSession('bash')).toBe(false);
  });

  it('returns true when an active (non-expired) entry matches the tool', () => {
    const entries = [{ tool: 'bash', expiry: Date.now() + 60_000 }];
    existsSpy.mockImplementation((p) => String(p) === TRUST_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === TRUST_FILE ? JSON.stringify({ entries }) : ''
    );
    expect(getActiveTrustSession('bash')).toBe(true);
  });

  it('returns false when the only entry is expired', () => {
    const entries = [{ tool: 'bash', expiry: Date.now() - 1000 }];
    existsSpy.mockImplementation((p) => String(p) === TRUST_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === TRUST_FILE ? JSON.stringify({ entries }) : ''
    );
    expect(getActiveTrustSession('bash')).toBe(false);
  });

  it('prunes expired entries by rewriting the trust file', () => {
    const entries = [
      { tool: 'bash', expiry: Date.now() - 1000 }, // expired
      { tool: 'node', expiry: Date.now() + 60_000 }, // active
    ];
    existsSpy.mockImplementation((p) => String(p) === TRUST_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === TRUST_FILE ? JSON.stringify({ entries }) : ''
    );
    getActiveTrustSession('bash'); // triggers prune because active.length !== entries.length
    expect(writeSpy).toHaveBeenCalled();
    const saved = JSON.parse(writeSpy.mock.calls[0][1] as string) as {
      entries: { tool: string }[];
    };
    expect(saved.entries).toHaveLength(1);
    expect(saved.entries[0].tool).toBe('node');
  });

  it('matches wildcard trust entries (trusts all tools)', () => {
    const entries = [{ tool: '*', expiry: Date.now() + 60_000 }];
    existsSpy.mockImplementation((p) => String(p) === TRUST_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === TRUST_FILE ? JSON.stringify({ entries }) : ''
    );
    expect(getActiveTrustSession('any_tool_name')).toBe(true);
  });

  it('returns false on malformed trust file JSON', () => {
    existsSpy.mockImplementation((p) => String(p) === TRUST_FILE);
    readSpy.mockImplementation((p) => (String(p) === TRUST_FILE ? 'not-json' : ''));
    expect(getActiveTrustSession('bash')).toBe(false);
  });
});

// ── writeTrustSession ─────────────────────────────────────────────────────────

describe('writeTrustSession', () => {
  it('creates a new trust file with the given entry when no file exists', () => {
    writeTrustSession('bash', 60_000);

    expect(writeSpy).toHaveBeenCalled();
    const saved = JSON.parse(writeSpy.mock.calls[0][1] as string) as {
      entries: { tool: string; expiry: number }[];
    };
    expect(saved.entries).toHaveLength(1);
    expect(saved.entries[0].tool).toBe('bash');
    expect(saved.entries[0].expiry).toBeGreaterThan(Date.now());

    expect(renameSpy).toHaveBeenCalled();
    const dest = renameSpy.mock.calls[0][1] as string;
    expect(dest).toBe(TRUST_FILE);
  });

  it('replaces an existing entry for the same tool (does not duplicate)', () => {
    const oldExpiry = Date.now() + 1000;
    existsSpy.mockImplementation((p) => String(p) === TRUST_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === TRUST_FILE
        ? JSON.stringify({ entries: [{ tool: 'bash', expiry: oldExpiry }] })
        : ''
    );
    writeTrustSession('bash', 3_600_000);

    const saved = JSON.parse(writeSpy.mock.calls[0][1] as string) as {
      entries: { tool: string; expiry: number }[];
    };
    // Must still be exactly one entry — replace, not append
    expect(saved.entries).toHaveLength(1);
    expect(saved.entries[0].expiry).toBeGreaterThan(oldExpiry);
  });

  it('prunes expired entries from other tools when writing a new session', () => {
    existsSpy.mockImplementation((p) => String(p) === TRUST_FILE);
    readSpy.mockImplementation((p) =>
      String(p) === TRUST_FILE
        ? JSON.stringify({
            entries: [
              { tool: 'old-tool', expiry: Date.now() - 1000 }, // expired — should be pruned
              { tool: 'active-tool', expiry: Date.now() + 60_000 }, // active — must survive
            ],
          })
        : ''
    );
    writeTrustSession('bash', 60_000);

    const saved = JSON.parse(writeSpy.mock.calls[0][1] as string) as {
      entries: { tool: string }[];
    };
    const tools = saved.entries.map((e) => e.tool);
    expect(tools).toContain('bash');
    expect(tools).toContain('active-tool');
    expect(tools).not.toContain('old-tool');
  });
});
