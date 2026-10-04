import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  entriesFromRecord,
  applyRecordToShards,
  compareVersions,
  entryCovers,
  lookupIndex,
  writeMeta,
  writeShard,
  shardOf,
  indexKey,
  INDEX_FRESH_MS,
  type Shard,
} from '../osv-index';
import { malRecord } from './zip-fixture';

describe('entriesFromRecord', () => {
  it('keeps exact versions', () => {
    const r = entriesFromRecord(
      'npm',
      malRecord('MAL-0000-0001', 'npm', 'node9-canary-a', { versions: ['1.0.0', '1.0.1'] })
    );
    expect(r?.rows.get('node9-canary-a')).toEqual({
      id: 'MAL-0000-0001',
      versions: ['1.0.0', '1.0.1'],
    });
  });
  it('an open range from 0 means every version', () => {
    const r = entriesFromRecord(
      'npm',
      malRecord('MAL-0000-0002', 'npm', 'node9-canary-b', { all: true })
    );
    expect(r?.rows.get('node9-canary-b')?.all).toBe(true);
  });
  it('a record naming a package and no versions covers the package', () => {
    const r = entriesFromRecord('npm', malRecord('MAL-0000-0003', 'npm', 'node9-canary-c'));
    expect(r?.rows.get('node9-canary-c')?.all).toBe(true);
  });
  it('bounded ranges are kept as ranges', () => {
    const rec = {
      id: 'MAL-0000-0004',
      affected: [
        {
          package: { name: 'node9-canary-d', ecosystem: 'npm' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }, { fixed: '2.0.5' }] }],
        },
      ],
    };
    expect(entriesFromRecord('npm', rec)?.rows.get('node9-canary-d')?.ranges).toEqual([
      { introduced: '2.0.0', fixed: '2.0.5', lastAffected: undefined },
    ]);
  });
  it('ignores non-MAL ids and other ecosystems; PyPI names are PEP 503 normalised', () => {
    expect(entriesFromRecord('npm', { id: 'GHSA-x', affected: [] })).toBeNull();
    const r = entriesFromRecord('npm', malRecord('MAL-0000-0005', 'PyPI', 'x'));
    expect(r?.rows.size).toBe(0);
    const py = entriesFromRecord('PyPI', malRecord('MAL-0000-0006', 'PyPI', 'Node9_Canary.Py'));
    expect([...(py?.rows.keys() ?? [])]).toEqual(['node9-canary-py']);
  });
});

describe('applyRecordToShards', () => {
  it('replaces an entry by id and drops it when withdrawn', () => {
    const shards = new Map<string, Shard>();
    const load = () => ({});
    const v1 = entriesFromRecord(
      'npm',
      malRecord('MAL-0000-0007', 'npm', 'node9-canary-e', { versions: ['1.0.0'] })
    )!;
    const v2 = entriesFromRecord(
      'npm',
      malRecord('MAL-0000-0007', 'npm', 'node9-canary-e', { versions: ['1.0.0', '2.0.0'] })
    )!;
    const gone = entriesFromRecord(
      'npm',
      malRecord('MAL-0000-0007', 'npm', 'node9-canary-e', { withdrawn: true })
    )!;
    applyRecordToShards(shards, v1, load);
    applyRecordToShards(shards, v2, load);
    const sid = shardOf('node9-canary-e');
    expect(shards.get(sid)?.['node9-canary-e']).toEqual([
      { id: 'MAL-0000-0007', versions: ['1.0.0', '2.0.0'] },
    ]);
    applyRecordToShards(shards, gone, load);
    expect(shards.get(sid)?.['node9-canary-e']).toBeUndefined();
  });
});

describe('compareVersions / entryCovers', () => {
  it('orders numerically and puts a pre-release before its release', () => {
    expect(compareVersions('1.10.0', '1.9.0')).toBe(1);
    expect(compareVersions('1.0.0-beta', '1.0.0')).toBe(-1);
    expect(compareVersions('2.0', '2.0.0')).toBe(0);
  });
  it('covers by exact version, by range, by all; unknown version is "unknown"', () => {
    expect(entryCovers({ id: 'M', versions: ['1.0.0'] }, '1.0.0')).toBe(true);
    expect(entryCovers({ id: 'M', versions: ['1.0.0'] }, '1.0.1')).toBe(false);
    expect(
      entryCovers({ id: 'M', ranges: [{ introduced: '2.0.0', fixed: '2.0.5' }] }, '2.0.4')
    ).toBe(true);
    expect(
      entryCovers({ id: 'M', ranges: [{ introduced: '2.0.0', fixed: '2.0.5' }] }, '2.0.5')
    ).toBe(false);
    expect(
      entryCovers({ id: 'M', ranges: [{ introduced: '0', lastAffected: '3.0.0' }] }, '3.0.0')
    ).toBe(true);
    expect(entryCovers({ id: 'M', all: true }, undefined)).toBe(true);
    expect(entryCovers({ id: 'M', versions: ['1.0.0'] }, undefined)).toBe('unknown');
  });
});

describe('lookupIndex', () => {
  let home: string;
  let origHome: string | undefined;
  // os.homedir() reads USERPROFILE on Windows, HOME elsewhere: set both.
  let origUserProfile: string | undefined;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-osv-'));
    origHome = process.env.HOME;
    process.env.HOME = home;
    origUserProfile = process.env.USERPROFILE;
    process.env.USERPROFILE = home;
  });
  afterEach(() => {
    process.env.HOME = origHome;
    if (origUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = origUserProfile;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('is unavailable without a meta file', () => {
    expect(lookupIndex('npm', 'node9-canary-a').status).toBe('unavailable');
  });
  it('finds a hit, a clean name, and reports freshness', () => {
    const key = indexKey('npm', 'node9-canary-a');
    writeShard('npm', shardOf(key), { [key]: [{ id: 'MAL-0000-0001', all: true }] });
    writeMeta('npm', {
      syncedAt: new Date().toISOString(),
      lastModifiedMs: 0,
      records: 1,
      mode: 'full',
    });
    const hit = lookupIndex('npm', 'Node9-Canary-A');
    expect(hit.status).toBe('hit');
    expect(lookupIndex('npm', 'node9-canary-zzz')).toEqual({ status: 'clean', fresh: true });
    writeMeta('npm', {
      syncedAt: new Date(Date.now() - INDEX_FRESH_MS - 1000).toISOString(),
      lastModifiedMs: 0,
      records: 1,
      mode: 'full',
    });
    expect(lookupIndex('npm', 'node9-canary-zzz')).toEqual({ status: 'clean', fresh: false });
  });
});
