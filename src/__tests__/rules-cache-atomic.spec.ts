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
import { readRulesCacheResilient, __resetRulesCacheStateForTest } from '../config';

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
    __resetRulesCacheStateForTest();
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
    __resetRulesCacheStateForTest();
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

  it('falls back to the last-known-good copy when the primary is corrupt (no fail-open)', async () => {
    // Primary corrupt, but the daemon's last-good sibling holds the real policy.
    fs.writeFileSync(cacheOf(), '{ truncated');
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.last-good.json'),
      JSON.stringify({ shields: ['aws'], rules: [] })
    );
    const raw = readRulesCacheResilient(cacheOf());
    // The whole point: enforcement is PRESERVED from the last-good copy, not
    // silently dropped to {} (fail-open). (The one-per-process fallback log is
    // best-effort and covered by the corrupt-log test above.)
    expect(raw.shields).toEqual(['aws']);
  });
});

describe('writeCache maintains a last-known-good backup', () => {
  let tmpHome: string;
  let origHome: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-lastgood-'));
    origHome = process.env.HOME;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    __resetRulesCacheStateForTest();
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  });
  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('writes both the primary and rules-cache.last-good.json with the same content', () => {
    __writeCacheForTest({
      fetchedAt: '2026-07-01T00:00:00Z',
      rules: [],
      shields: ['aws'],
      workspaceId: 'ws-1',
    } as unknown as Parameters<typeof __writeCacheForTest>[0]);
    const primary = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), 'utf-8')
    );
    const backup = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'rules-cache.last-good.json'), 'utf-8')
    );
    expect(backup).toEqual(primary);
    expect(backup.shields).toEqual(['aws']);
  });
});

describe('readRulesCacheResilient — round-2 F4 hardening (/code-review #7, #2, #3)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;
  let n9: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-f4-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    __resetRulesCacheStateForTest();
    n9 = path.join(tmpHome, '.node9');
    fs.mkdirSync(n9, { recursive: true });
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('#7: a present-but-UNREADABLE primary (EACCES) reaches the last-good backup instead of silently dropping enforcement', () => {
    const primary = path.join(n9, 'rules-cache.json');
    const backup = path.join(n9, 'rules-cache.last-good.json');
    fs.writeFileSync(primary, '{"shields":["aws"]}');
    fs.writeFileSync(backup, '{"shields":["aws"],"from":"backup"}');

    const realRead = fs.readFileSync.bind(fs);
    vi.spyOn(fs, 'readFileSync').mockImplementation(((p: fs.PathOrFileDescriptor, o?: unknown) => {
      if (String(p) === primary) {
        throw Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' });
      }
      return realRead(p as never, o as never);
    }) as typeof fs.readFileSync);

    const out = readRulesCacheResilient(primary);
    // Before F4: existed stayed false on a read THROW, so the backup and the
    // log were both skipped and {} silently dropped every mandated shield.
    expect(out).toEqual({ shields: ['aws'], from: 'backup' });
  });

  it('#2: with no usable disk copy, a long-lived process falls back to the last cache it successfully parsed', () => {
    const primary = path.join(n9, 'rules-cache.json');
    // 1. A successful parse seeds the in-process memo (the daemon's normal state).
    fs.writeFileSync(primary, '{"shields":["memo-shield"]}');
    expect(readRulesCacheResilient(primary)).toEqual({ shields: ['memo-shield'] });
    // 2. Disk turns hostile: primary corrupt, no backup.
    fs.writeFileSync(primary, '{"shields":['); // torn/corrupt
    const out = readRulesCacheResilient(primary);
    // Before F4: {} — the mandated shield vanished. Now: the memo holds the line.
    expect(out).toEqual({ shields: ['memo-shield'] });
  });

  it('#3: the corruption log re-arms after 5 minutes instead of latching once per process', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-07-24T12:00:00Z'));
    const primary = path.join(n9, 'rules-cache.json');
    const debugLog = path.join(n9, 'hook-debug.log');
    const logLines = () =>
      fs.existsSync(debugLog)
        ? fs.readFileSync(debugLog, 'utf-8').trim().split('\n').filter(Boolean).length
        : 0;

    fs.writeFileSync(primary, '{"broken":'); // corrupt, no backup, no memo hit needed — any kind logs
    readRulesCacheResilient(primary);
    const afterFirst = logLines();
    expect(afterFirst).toBeGreaterThan(0);

    // Within the window: silent.
    vi.setSystemTime(new Date('2026-07-24T12:02:00Z'));
    readRulesCacheResilient(primary);
    expect(logLines()).toBe(afterFirst);

    // Past the window: logs again (recurring corruption stays visible).
    vi.setSystemTime(new Date('2026-07-24T12:06:00Z'));
    readRulesCacheResilient(primary);
    expect(logLines()).toBeGreaterThan(afterFirst);
  });
});
