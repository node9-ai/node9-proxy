// runPackageCheck on the inputs the real caller produces: the orchestrator
// passes the agent's tool name ('Bash') and its args ({ command }). Network is
// a stubbed global fetch keyed by URL; the local index lives in a temp HOME.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { runPackageCheck, type PackageCheckConfig } from '../check';
import { writeMeta, writeShard, shardOf, indexKey } from '../osv-index';

const CFG: PackageCheckConfig = {
  enabled: true,
  onMalicious: 'block',
  registrySignals: true,
  maxAgeHours: 48,
  onlineFallback: true,
  allow: [],
};
const OLD = '2020-01-01T00:00:00Z';

let home: string;
let origHome: string | undefined;
let routes: Record<string, () => Response | Promise<Response>>;
let calls: string[];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
function npmDoc(latest: string, opts: { modified?: string; installScript?: boolean } = {}) {
  return json({
    name: 'x',
    modified: opts.modified ?? OLD,
    'dist-tags': { latest },
    versions: { [latest]: { hasInstallScript: opts.installScript || undefined } },
  });
}
function indexWith(eco: 'npm' | 'PyPI', name: string, entries: object[], fresh = true) {
  const key = indexKey(eco, name);
  writeShard(eco, shardOf(key), { [key]: entries as never });
  writeMeta(eco, {
    syncedAt: fresh ? new Date().toISOString() : OLD,
    lastModifiedMs: 0,
    records: 1,
    mode: 'full',
  });
}
const bash = (command: string) => ['Bash', { command }] as const;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-pkgcheck-'));
  origHome = process.env.HOME;
  process.env.HOME = home;
  process.env.NODE9_NPM_REGISTRY_URL = 'http://registry.test';
  process.env.NODE9_PYPI_URL = 'http://pypi.test';
  process.env.NODE9_OSV_API_URL = 'http://osv.test';
  routes = {};
  calls = [];
  vi.stubGlobal('fetch', async (url: string) => {
    calls.push(String(url));
    const route = routes[String(url)];
    if (!route) throw new Error(`unexpected fetch ${url}`);
    return route();
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  process.env.HOME = origHome;
  delete process.env.NODE9_NPM_REGISTRY_URL;
  delete process.env.NODE9_PYPI_URL;
  delete process.env.NODE9_OSV_API_URL;
  fs.rmSync(home, { recursive: true, force: true });
});

describe('runPackageCheck — malicious', () => {
  it('blocks a pinned version the local index covers, advisory id in the reason', async () => {
    indexWith('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', versions: ['1.0.0'] }]);
    routes['http://registry.test/node9-canary-mal'] = () => npmDoc('1.0.0');
    const r = await runPackageCheck(...bash('npm install node9-canary-mal@1.0.0'), CFG);
    expect(r.verdict).toBe('block');
    expect(r.reason).toContain('MAL-0000-0001');
    expect(r.reason).toContain('node9-canary-mal@1.0.0');
  });
  it('resolves an unpinned install to latest through the registry, then blocks', async () => {
    indexWith('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', versions: ['2.0.0'] }]);
    routes['http://registry.test/node9-canary-mal'] = () => npmDoc('2.0.0');
    const r = await runPackageCheck(...bash('npx node9-canary-mal'), CFG);
    expect(r.verdict).toBe('block');
  });
  it('a record for other versions only, version unknown → review, not block', async () => {
    indexWith('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', versions: ['9.9.9'] }]);
    const r = await runPackageCheck(...bash('npm i node9-canary-mal'), {
      ...CFG,
      registrySignals: false,
    });
    expect(r.verdict).toBe('review');
    expect(r.findings[0].kind).toBe('malicious-unpinned');
  });
  it('a pinned version outside the record is clean', async () => {
    indexWith('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', versions: ['9.9.9'] }]);
    const r = await runPackageCheck(...bash('npm i node9-canary-mal@1.0.0'), {
      ...CFG,
      registrySignals: false,
    });
    expect(r.verdict).toBe('allow');
  });
  it('onMalicious: review downgrades the block', async () => {
    indexWith('PyPI', 'node9-canary-py', [{ id: 'MAL-0000-0002', all: true }]);
    const r = await runPackageCheck(...bash('pip install node9_canary.py==1.0'), {
      ...CFG,
      registrySignals: false,
      onMalicious: 'review',
    });
    expect(r.verdict).toBe('review');
    expect(r.reason).toContain('MAL-0000-0002');
  });
  it('falls back to OSV online when there is no index', async () => {
    routes['http://registry.test/node9-canary-mal'] = () => npmDoc('3.0.0');
    routes['http://osv.test/v1/querybatch'] = () =>
      json({ results: [{ vulns: [{ id: 'GHSA-xxxx' }, { id: 'MAL-0000-0003' }] }] });
    const r = await runPackageCheck(...bash('pnpm add node9-canary-mal'), CFG);
    expect(r.verdict).toBe('block');
    expect(r.reason).toContain('MAL-0000-0003');
    expect(r.reason).not.toContain('GHSA');
  });
  it('a fresh index that has nothing makes NO online call', async () => {
    indexWith('npm', 'node9-canary-other', [{ id: 'MAL-0000-0004', all: true }]);
    const r = await runPackageCheck(...bash('npm i node9-canary-clean@1.0.0'), {
      ...CFG,
      registrySignals: false,
    });
    expect(r.verdict).toBe('allow');
    expect(calls).toEqual([]);
  });
});

describe('runPackageCheck — registry signals', () => {
  it('reviews an npm package with an install script', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-native'] = () =>
      npmDoc('1.0.0', { installScript: true });
    const r = await runPackageCheck(...bash('npm i node9-canary-native'), CFG);
    expect(r.verdict).toBe('review');
    expect(r.reason).toContain('install script');
  });
  it('reviews a package published inside maxAgeHours', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-young'] = () =>
      npmDoc('1.0.0', { modified: new Date(Date.now() - 3 * 3_600_000).toISOString() });
    const r = await runPackageCheck(...bash('yarn add node9-canary-young'), CFG);
    expect(r.verdict).toBe('review');
    expect(r.findings.map((f) => f.kind)).toEqual(['new']);
  });
  it('PyPI age comes from the release upload time', async () => {
    indexWith('PyPI', 'node9-canary-other', []);
    routes['http://pypi.test/pypi/node9-canary-young/json'] = () =>
      json({
        info: { version: '0.1.0' },
        urls: [{ upload_time_iso_8601: new Date(Date.now() - 3_600_000).toISOString() }],
      });
    const r = await runPackageCheck(...bash('uv add node9-canary-young'), CFG);
    expect(r.verdict).toBe('review');
  });
  it('an old package with no install script is allowed', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-old'] = () => npmDoc('1.0.0');
    expect((await runPackageCheck(...bash('npm i node9-canary-old'), CFG)).verdict).toBe('allow');
  });
});

describe('runPackageCheck — fails open', () => {
  it('registry and OSV both down: allow, with recorded misses', async () => {
    routes['http://registry.test/node9-canary-x'] = () => {
      throw new Error('ECONNREFUSED');
    };
    routes['http://osv.test/v1/querybatch'] = () => json({}, 503);
    const r = await runPackageCheck(...bash('npm i node9-canary-x'), CFG);
    expect(r.verdict).toBe('allow');
    expect(r.misses.length).toBeGreaterThanOrEqual(2);
  });
  it('no endpoint at all (NODE9_TESTING without overrides): allow with a miss, no fetch', async () => {
    delete process.env.NODE9_NPM_REGISTRY_URL;
    delete process.env.NODE9_OSV_API_URL;
    const r = await runPackageCheck(...bash('npm i node9-canary-x'), CFG);
    expect(r.verdict).toBe('allow');
    expect(r.misses.length).toBeGreaterThan(0);
    expect(calls).toEqual([]);
  });
});

describe('runPackageCheck — scope', () => {
  it('skips non-shell tools, non-install commands, disabled config and allow-listed names', async () => {
    indexWith('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', all: true }]);
    expect(
      (await runPackageCheck('Write', { command: 'npm i node9-canary-mal' }, CFG)).verdict
    ).toBe('allow');
    expect((await runPackageCheck(...bash('npm run build'), CFG)).verdict).toBe('allow');
    expect(
      (await runPackageCheck(...bash('npm i node9-canary-mal'), { ...CFG, enabled: false })).verdict
    ).toBe('allow');
    expect(
      (
        await runPackageCheck(...bash('npm i node9-canary-mal'), {
          ...CFG,
          allow: ['node9-canary-*'],
        })
      ).verdict
    ).toBe('allow');
    expect(calls).toEqual([]);
  });
});
