import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { changedIds, fullSync, incrementalSync } from '../osv-sync';
import { lookupIndex, readMeta } from '../osv-index';
import { buildZip, malRecord } from './zip-fixture';

const BUCKET = 'http://bucket.test';
let home: string;
let origHome: string | undefined;
// os.homedir() reads USERPROFILE on Windows, HOME elsewhere: set both.
let origUserProfile: string | undefined;
let routes: Record<string, () => Response>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-osvsync-'));
  origHome = process.env.HOME;
  process.env.HOME = home;
  origUserProfile = process.env.USERPROFILE;
  process.env.USERPROFILE = home;
  routes = {};
  vi.stubGlobal('fetch', async (url: string) => {
    const r = routes[String(url)];
    if (!r) return new Response('not found', { status: 404 });
    return r();
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  process.env.HOME = origHome;
  if (origUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = origUserProfile;
  fs.rmSync(home, { recursive: true, force: true });
});

describe('changedIds', () => {
  const csv = [
    '2026-10-02T10:00:00.123456Z,MAL-0000-0003',
    '2026-10-02T09:00:00Z,GHSA-aaaa',
    '2026-10-02T08:00:00Z,MAL-0000-0002',
    '2026-10-01T00:00:00Z,MAL-0000-0001',
  ].join('\n');
  it('returns MAL ids newer than the watermark, newest first, skipping others', () => {
    expect(changedIds(csv, Date.parse('2026-10-02T07:00:00Z'))).toEqual({
      ids: ['MAL-0000-0003', 'MAL-0000-0002'],
      complete: true,
    });
  });
  it('re-reads a one-second overlap at the boundary', () => {
    expect(changedIds(csv, Date.parse('2026-10-02T08:00:00.500Z')).ids).toContain('MAL-0000-0002');
  });
});

describe('fullSync + incrementalSync', () => {
  it('builds the index from all.zip (MAL entries only), then applies changes', async () => {
    const zip = buildZip(
      [
        {
          name: 'MAL-0000-0001.json',
          data: JSON.stringify(
            malRecord('MAL-0000-0001', 'npm', 'node9-canary-a', { versions: ['1.0.0'] })
          ),
        },
        {
          name: 'MAL-0000-0002.json',
          data: JSON.stringify(malRecord('MAL-0000-0002', 'npm', 'node9-canary-b', { all: true })),
        },
        {
          name: 'GHSA-zzzz.json',
          data: JSON.stringify(malRecord('GHSA-zzzz', 'npm', 'node9-canary-c')),
        },
        { name: 'MAL-0000-0009.json', data: '{not json' },
      ],
      { zip64: true }
    );
    routes[`${BUCKET}/npm/all.zip`] = () => new Response(zip);
    expect(await fullSync('npm', BUCKET)).toBe(2);
    expect(lookupIndex('npm', 'node9-canary-a').status).toBe('hit');
    expect(lookupIndex('npm', 'node9-canary-c').status).toBe('clean');
    expect(
      fs.readdirSync(path.join(home, '.node9', 'osv', 'npm')).some((f) => f.endsWith('.tmp'))
    ).toBe(false);

    // A later change: canary-a is withdrawn, canary-d is new.
    const since = readMeta('npm')!.lastModifiedMs;
    routes[`${BUCKET}/npm/modified_id.csv`] = () =>
      new Response(
        [
          '2026-10-03T00:00:00Z,MAL-0000-0004',
          '2026-10-03T00:00:00Z,MAL-0000-0001',
          '2026-09-01T00:00:00Z,MAL-0000-0002',
        ].join('\n')
      );
    routes[`${BUCKET}/npm/MAL-0000-0004.json`] = () =>
      new Response(
        JSON.stringify(
          malRecord('MAL-0000-0004', 'npm', 'node9-canary-d', {
            all: true,
            modified: '2026-10-03T00:00:00Z',
          })
        )
      );
    routes[`${BUCKET}/npm/MAL-0000-0001.json`] = () =>
      new Response(
        JSON.stringify(
          malRecord('MAL-0000-0001', 'npm', 'node9-canary-a', {
            withdrawn: true,
            modified: '2026-10-03T00:00:00Z',
          })
        )
      );
    expect(await incrementalSync('npm', BUCKET, since)).toBe(2);
    expect(lookupIndex('npm', 'node9-canary-a').status).toBe('clean');
    expect(lookupIndex('npm', 'node9-canary-d').status).toBe('hit');
    expect(lookupIndex('npm', 'node9-canary-b').status).toBe('hit');
    expect(readMeta('npm')!.mode).toBe('incremental');
  });

  it('a failed record fetch writes nothing (the window is retried next run)', async () => {
    routes[`${BUCKET}/npm/modified_id.csv`] = () =>
      new Response('2026-10-03T00:00:00Z,MAL-0000-0005');
    routes[`${BUCKET}/npm/MAL-0000-0005.json`] = () => new Response('busy', { status: 503 });
    await expect(incrementalSync('npm', BUCKET, 0)).rejects.toThrow(/HTTP 503/);
    expect(readMeta('npm')).toBeNull();
  });

  // /code-review: a 404 used to throw, so one removed record failed every run
  // until the weekly rebuild and the index went stale for days.
  it('a record removed upstream (404) is skipped and the rest still apply', async () => {
    routes[`${BUCKET}/npm/modified_id.csv`] = () =>
      new Response(
        ['2026-10-03T00:00:00Z,MAL-0000-0006', '2026-10-03T00:00:00Z,MAL-0000-0005'].join('\n')
      );
    routes[`${BUCKET}/npm/MAL-0000-0006.json`] = () =>
      new Response(
        JSON.stringify(
          malRecord('MAL-0000-0006', 'npm', 'node9-canary-f', {
            all: true,
            modified: '2026-10-03T00:00:00Z',
          })
        )
      );
    expect(await incrementalSync('npm', BUCKET, 0)).toBe(1);
    expect(lookupIndex('npm', 'node9-canary-f').status).toBe('hit');
  });

  it('an archive with no MAL records is rejected and leaves no index', async () => {
    routes[`${BUCKET}/PyPI/all.zip`] = () =>
      new Response(buildZip([{ name: 'GHSA-1.json', data: '{}' }]));
    await expect(fullSync('PyPI', BUCKET)).rejects.toThrow(/no MAL- records/);
    expect(readMeta('PyPI')).toBeNull();
  });
});
