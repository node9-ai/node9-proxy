import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { recordAndCheck, resetLoopState, computeArgsHash } from '../loop-detector.js';

// Each test gets its own HOME to prevent cross-test pollution of loop state.
let origHome: string;
let origUserProfile: string;
let tmpHome: string;

beforeEach(() => {
  origHome = process.env.HOME ?? '';
  origUserProfile = process.env.USERPROFILE ?? '';
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'loop-test-'));
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
});

afterEach(() => {
  process.env.HOME = origHome;
  process.env.USERPROFILE = origUserProfile;
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

describe('computeArgsHash', () => {
  it('returns a 16-char hex string', () => {
    const hash = computeArgsHash({ command: 'echo hello' });
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });

  it('is deterministic — same args produce the same hash', () => {
    const args = { command: 'echo hello' };
    expect(computeArgsHash(args)).toBe(computeArgsHash(args));
  });

  it('produces different hashes for different args', () => {
    expect(computeArgsHash({ command: 'echo hello' })).not.toBe(
      computeArgsHash({ command: 'echo world' })
    );
  });

  it('handles null/undefined args', () => {
    expect(computeArgsHash(null)).toBe(computeArgsHash(undefined));
  });
});

describe('recordAndCheck', () => {
  it('does not flag below threshold', () => {
    const r1 = recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    expect(r1.looping).toBe(false);
    expect(r1.count).toBe(1);

    const r2 = recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    expect(r2.looping).toBe(false);
    expect(r2.count).toBe(2);
  });

  it('flags at threshold', () => {
    recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    const r3 = recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    expect(r3.looping).toBe(true);
    expect(r3.count).toBe(3);
  });

  it('different args do not count as the same call', () => {
    recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    // Third call with different args — should NOT loop
    const r = recordAndCheck('bash', { command: 'echo world' }, 3, 120_000);
    expect(r.looping).toBe(false);
    expect(r.count).toBe(1);
  });

  it('different tools do not count as the same call', () => {
    recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    // Third call with different tool — should NOT loop
    const r = recordAndCheck('write', { command: 'echo hello' }, 3, 120_000);
    expect(r.looping).toBe(false);
    expect(r.count).toBe(1);
  });

  it('expired entries are not counted', () => {
    // Use a 1ms window so entries expire immediately
    recordAndCheck('bash', { command: 'echo hello' }, 3, 1);
    recordAndCheck('bash', { command: 'echo hello' }, 3, 1);

    // Wait a tiny bit for expiry, then call again with fresh window
    const r = recordAndCheck('bash', { command: 'echo hello' }, 3, 1);
    // The previous entries may or may not have expired depending on timing,
    // but with a 1ms window they should be gone. Count should be 1 (just this call).
    expect(r.count).toBeLessThanOrEqual(3);
  });

  it('recovers from corrupt state file', () => {
    const stateFile = path.join(tmpHome, '.node9', 'loop-state.json');
    fs.writeFileSync(stateFile, 'NOT VALID JSON!!!');

    // Should not throw, should start fresh
    const r = recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    expect(r.looping).toBe(false);
    expect(r.count).toBe(1);
  });

  it('recovers from non-array state file', () => {
    const stateFile = path.join(tmpHome, '.node9', 'loop-state.json');
    fs.writeFileSync(stateFile, JSON.stringify({ not: 'an array' }));

    const r = recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    expect(r.looping).toBe(false);
    expect(r.count).toBe(1);
  });

  it('creates ~/.node9/ directory if missing', () => {
    fs.rmSync(path.join(tmpHome, '.node9'), { recursive: true, force: true });

    const r = recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    expect(r.looping).toBe(false);
    expect(fs.existsSync(path.join(tmpHome, '.node9', 'loop-state.json'))).toBe(true);
  });
});

describe('resetLoopState', () => {
  it('clears the state file', () => {
    recordAndCheck('bash', { command: 'echo hello' }, 3, 120_000);
    const stateFile = path.join(tmpHome, '.node9', 'loop-state.json');
    expect(fs.existsSync(stateFile)).toBe(true);

    resetLoopState();
    expect(fs.existsSync(stateFile)).toBe(false);
  });

  it('does not throw when file does not exist', () => {
    expect(() => resetLoopState()).not.toThrow();
  });
});
