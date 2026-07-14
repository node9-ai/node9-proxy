/**
 * Policy-sync health record (fix spec: policy-sync-fix-spec.md, Commit 1 / D3).
 *
 * The bug this guards against: a sync that silently fails (or a daemon that
 * never runs) leaves the policy cache stale with NO signal. These tests pin the
 * observability primitives:
 *   - recordSyncHealth: success resets failures + stamps lastCheckedAt; failure
 *     increments consecutiveFailures + records lastError, and must NOT advance
 *     lastCheckedAt (health ≠ freshness).
 *   - lastCheckedAt (any completed request, incl. 304) vs lastChangedAt (content
 *     changed) — the distinction that makes "healthy but unchanged" separable
 *     from "broken for days".
 *   - isPolicyStale / stalenessThresholdMs — the age gate used to surface it.
 *
 * Real fs against a temp $HOME (via os.homedir spy) — no fs mocks, so a path/
 * write bug can't hide behind a stub.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

process.env.NODE9_TESTING = '1';

import {
  readSyncHealth,
  recordSyncHealth,
  isPolicyStale,
  stalenessThresholdMs,
} from '../daemon/sync';

const HOUR = 3_600_000;
let tmp: string;
let homeSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-synchealth-'));
  fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
  homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmp);
});
afterEach(() => {
  homeSpy.mockRestore();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('recordSyncHealth / readSyncHealth', () => {
  it('defaults to zero failures when no health file exists', () => {
    expect(readSyncHealth()).toEqual({ consecutiveFailures: 0 });
  });

  it('a successful check stamps lastCheckedAt and resets failures + clears lastError', () => {
    recordSyncHealth({ ok: false, error: 'boom' });
    recordSyncHealth({ ok: false, error: 'boom2' });
    expect(readSyncHealth().consecutiveFailures).toBe(2);

    recordSyncHealth({ ok: true });
    const h = readSyncHealth();
    expect(h.consecutiveFailures).toBe(0);
    expect(h.lastCheckedAt).toBeTypeOf('string');
    expect(h.lastError).toBeUndefined();
    expect(h.lastErrorAt).toBeUndefined();
  });

  it('lastChangedAt advances only on changed:true, not on a plain (304) success', () => {
    recordSyncHealth({ ok: true }); // 304 — contacted, nothing changed
    expect(readSyncHealth().lastChangedAt).toBeUndefined();
    expect(readSyncHealth().lastCheckedAt).toBeTypeOf('string');

    recordSyncHealth({ ok: true, changed: true }); // 200 — content changed
    expect(readSyncHealth().lastChangedAt).toBeTypeOf('string');
  });

  it('a failure increments failures + records lastError but does NOT advance lastCheckedAt', () => {
    recordSyncHealth({ ok: true });
    const checkedAt = readSyncHealth().lastCheckedAt;

    recordSyncHealth({ ok: false, error: 'network down' });
    const h = readSyncHealth();
    expect(h.consecutiveFailures).toBe(1);
    expect(h.lastError).toBe('network down');
    expect(h.lastErrorAt).toBeTypeOf('string');
    expect(h.lastCheckedAt).toBe(checkedAt); // health ≠ freshness — must not move
  });
});

describe('stalenessThresholdMs', () => {
  it('is 3× the interval, clamped to [3h, 24h]', () => {
    expect(stalenessThresholdMs(1 * HOUR)).toBe(3 * HOUR); // 3×1h = 3h (== floor)
    expect(stalenessThresholdMs(2 * HOUR)).toBe(6 * HOUR); // 3×2h = 6h
    expect(stalenessThresholdMs(60_000)).toBe(3 * HOUR); // tiny → floor 3h
    expect(stalenessThresholdMs(12 * HOUR)).toBe(24 * HOUR); // 3×12h = 36h → cap 24h
  });
});

describe('isPolicyStale', () => {
  const seedCache = (fetchedAt: string) =>
    fs.writeFileSync(
      path.join(tmp, '.node9', 'rules-cache.json'),
      JSON.stringify({ fetchedAt, rules: [] }),
      'utf-8'
    );

  it('is NOT stale on a truly uninitialised machine (no health, no cache) — first run, not an alarm', () => {
    expect(isPolicyStale()).toBe(false);
  });

  it('is fresh immediately after a successful check', () => {
    recordSyncHealth({ ok: true });
    expect(isPolicyStale()).toBe(false);
  });

  it('is stale when the last successful check is older than the threshold', () => {
    recordSyncHealth({ ok: true });
    const eightDaysLater = Date.now() + 8 * 24 * HOUR;
    expect(isPolicyStale(eightDaysLater)).toBe(true);
  });

  it('falls back to the cache fetchedAt when there is no health record (upgrade / the real-bug case)', () => {
    // No sync-health.json, but a week-old cache exists → must read STALE.
    seedCache(new Date(Date.now() - 8 * 24 * HOUR).toISOString());
    expect(isPolicyStale()).toBe(true);
    // A fresh cache → not stale.
    seedCache(new Date().toISOString());
    expect(isPolicyStale()).toBe(false);
  });

  it('accepts an injected health record (no re-read)', () => {
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * HOUR).toISOString();
    expect(isPolicyStale(Date.now(), { consecutiveFailures: 0, lastCheckedAt: eightDaysAgo })).toBe(
      true
    );
  });
});
