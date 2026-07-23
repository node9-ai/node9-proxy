// src/__tests__/rules-cache-atomic.spec.ts
//
// Regression for the non-deterministic shield/policy fail-open (task #17).
//
// Root cause: the daemon rewrote ~/.node9/rules-cache.json with a plain,
// non-atomic fs.writeFileSync, while a hook's getConfig() read it with a
// JSON.parse inside a fail-OPEN catch. A read overlapping a write got a
// partial file → parse threw → ALL cloud enforcement (shields, managed mode)
// was silently dropped for that call → a shield-blocked command was allowed.
// Non-deterministic (overlap-dependent) and fail-open.
//
// Two fixes, both covered here:
//   1. writeCache writes atomically (temp + rename) — no partial file is ever
//      visible to a concurrent reader.
//   2. the reader retries a torn read and, on a present-but-corrupt cache,
//      logs instead of silently dropping enforcement.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { __writeCacheForTest } from '../daemon/sync';
import { readRulesCacheResilient } from '../config';

describe('writeCache — atomic write (no partial file visible)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-atomic-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('renames a temp file onto rules-cache.json instead of truncating it in place', async () => {
    const target = path.join(tmpHome, '.node9', 'rules-cache.json');

    const renameSpy = vi.spyOn(fs, 'renameSync');
    const writeSpy = vi.spyOn(fs, 'writeFileSync');

    __writeCacheForTest({
      fetchedAt: '2026-07-01T00:00:00Z',
      rules: [],
      shields: ['aws'],
      workspaceId: 'ws-1',
    } as unknown as Parameters<typeof __writeCacheForTest>[0]);

    // The final path must be produced by an atomic rename...
    const renamedToTarget = renameSpy.mock.calls.some(([, dst]) => dst === target);
    expect(renamedToTarget).toBe(true);
    // ...never by a direct in-place write to the target (the old truncating bug).
    const directTargetWrite = writeSpy.mock.calls.some(([p]) => p === target);
    expect(directTargetWrite).toBe(false);

    // And the resulting file is complete, valid JSON carrying the payload.
    const parsed = JSON.parse(fs.readFileSync(target, 'utf-8'));
    expect(parsed.shields).toEqual(['aws']);
  });

  it('leaves no .tmp residue after a successful write', async () => {
    __writeCacheForTest({
      fetchedAt: '2026-07-01T00:00:00Z',
      rules: [],
      shields: [],
      workspaceId: 'ws-1',
    } as unknown as Parameters<typeof __writeCacheForTest>[0]);
    const leftovers = fs
      .readdirSync(path.join(tmpHome, '.node9'))
      .filter((f) => f.includes('.tmp'));
    expect(leftovers).toEqual([]);
  });
});

describe('readRulesCacheResilient — no silent fail-open on a torn/corrupt read', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  const cacheOf = () => path.join(tmpHome, '.node9', 'rules-cache.json');

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-read-'));
    origHome = process.env.HOME;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('parses a whole file', async () => {
    fs.writeFileSync(cacheOf(), JSON.stringify({ shields: ['aws'], rules: [] }));
    const raw = readRulesCacheResilient(cacheOf());
    expect(raw.shields).toEqual(['aws']);
  });

  it('returns {} for an ABSENT cache without logging (no cloud policy is normal)', async () => {
    const appendSpy = vi.spyOn(fs, 'appendFileSync');
    const raw = readRulesCacheResilient(cacheOf()); // file does not exist
    expect(raw).toEqual({});
    const loggedUnreadable = appendSpy.mock.calls.some(([, data]) =>
      String(data).includes('RULES_CACHE_UNREADABLE')
    );
    expect(loggedUnreadable).toBe(false);
  });

  it('recovers a torn read on retry instead of dropping enforcement', async () => {
    const good = JSON.stringify({ shields: ['aws'], rules: [] });
    const realRead = fs.readFileSync;
    let n = 0;
    vi.spyOn(fs, 'readFileSync').mockImplementation(((p: fs.PathOrFileDescriptor, o?: unknown) => {
      if (typeof p === 'string' && p.endsWith('rules-cache.json')) {
        n += 1;
        if (n === 1) return good.slice(0, Math.floor(good.length * 0.5)); // partial/torn
        return good; // retry sees the complete (atomically renamed) file
      }
      return (realRead as (a: unknown, b: unknown) => unknown)(p, o);
    }) as typeof fs.readFileSync);

    const raw = readRulesCacheResilient(cacheOf());
    expect(raw.shields).toEqual(['aws']); // recovered, NOT dropped
    expect(n).toBeGreaterThanOrEqual(2); // proves a retry happened
  });

  it('logs (does NOT silently drop) when a present cache is corrupt past retries', async () => {
    fs.writeFileSync(cacheOf(), '{ this is not valid json ');
    const appendSpy = vi.spyOn(fs, 'appendFileSync');
    const raw = readRulesCacheResilient(cacheOf());
    expect(raw).toEqual({}); // still falls back (no hard-brick)...
    const loggedUnreadable = appendSpy.mock.calls.some(([, data]) =>
      String(data).includes('RULES_CACHE_UNREADABLE')
    );
    expect(loggedUnreadable).toBe(true); // ...but never silently
  });
});
