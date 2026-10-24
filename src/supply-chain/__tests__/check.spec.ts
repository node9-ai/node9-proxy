// runPackageCheck on the inputs the real caller produces: the orchestrator
// passes the agent's tool name ('Bash') and its args ({ command }). Network is
// a stubbed global fetch keyed by URL; the local index lives in a temp HOME.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { runPackageCheck, type PackageCheckConfig } from '../check';
import { registryInfo } from '../registry';
import { writeMeta, writeShard, shardOf, indexKey } from '../osv-index';
import type { PackageEcosystem } from '@node9/policy-engine';

const CFG: PackageCheckConfig = {
  enabled: true,
  onMalicious: 'block',
  newPackage: 'review',
  installScript: 'review',
  maxAgeHours: 48,
  onlineFallback: true,
  allow: [],
};
const OLD = '2020-01-01T00:00:00Z';

let home: string;
let origHome: string | undefined;
// os.homedir() reads USERPROFILE on Windows, HOME elsewhere: set both.
let origUserProfile: string | undefined;
let routes: Record<string, (init?: RequestInit) => Response | Promise<Response>>;
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
function indexWith(eco: PackageEcosystem, name: string, entries: object[], fresh = true) {
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
  origUserProfile = process.env.USERPROFILE;
  process.env.USERPROFILE = home;
  process.env.NODE9_NPM_REGISTRY_URL = 'http://registry.test';
  process.env.NODE9_PYPI_URL = 'http://pypi.test';
  process.env.NODE9_OSV_API_URL = 'http://osv.test';
  routes = {};
  calls = [];
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    calls.push(String(url));
    const route = routes[String(url)];
    if (!route) throw new Error(`unexpected fetch ${url}`);
    return route(init);
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  process.env.HOME = origHome;
  if (origUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = origUserProfile;
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
      newPackage: 'off',
      installScript: 'off',
    });
    expect(r.verdict).toBe('review');
    expect(r.findings[0].kind).toBe('malicious-unpinned');
  });
  it('a pinned version outside the record is clean', async () => {
    indexWith('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', versions: ['9.9.9'] }]);
    const r = await runPackageCheck(...bash('npm i node9-canary-mal@1.0.0'), {
      ...CFG,
      newPackage: 'off',
      installScript: 'off',
    });
    expect(r.verdict).toBe('allow');
  });
  it('onMalicious: review downgrades the block', async () => {
    indexWith('PyPI', 'node9-canary-py', [{ id: 'MAL-0000-0002', all: true }]);
    const r = await runPackageCheck(...bash('pip install node9_canary.py==1.0'), {
      ...CFG,
      newPackage: 'off',
      installScript: 'off',
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
      newPackage: 'off',
      installScript: 'off',
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

// /code-review: packages past the 10th used to be allowed unchecked, so ten
// benign names in front of a malicious one waved it through.
describe('runPackageCheck — many packages in one command', () => {
  it('the 11th package is still checked against the local index', async () => {
    indexWith('npm', 'node9-canary-mal', [{ id: 'MAL-0000-0001', all: true }]);
    const benign = Array.from({ length: 10 }, (_, i) => `node9-canary-ok${i}@1.0.0`).join(' ');
    const r = await runPackageCheck(...bash(`npm i ${benign} node9-canary-mal@1.0.0`), {
      ...CFG,
      newPackage: 'off',
      installScript: 'off',
    });
    expect(r.verdict).toBe('block');
    expect(r.reason).toContain('MAL-0000-0001');
  });
  it('packages past the 10th make no network call', async () => {
    indexWith('npm', 'node9-canary-other', [], false); // stale index: a miss would go online
    routes['http://osv.test/v1/querybatch'] = () => json({ results: [{ vulns: [] }] });
    const pkgs = Array.from({ length: 12 }, (_, i) => `node9-canary-p${i}@1.0.0`).join(' ');
    await runPackageCheck(...bash(`npm i ${pkgs}`), {
      ...CFG,
      newPackage: 'off',
      installScript: 'off',
    });
    expect(calls.filter((c) => c.includes('querybatch'))).toHaveLength(10);
  });
});

describe('runPackageCheck — miss text past the network cap', () => {
  it('names the cap, not the config, for packages 11+ with no index', async () => {
    const pkgs = Array.from({ length: 11 }, (_, i) => `node9-canary-p${i}@1.0.0`).join(' ');
    routes['http://osv.test/v1/querybatch'] = () => json({ results: [{ vulns: [] }] });
    for (let i = 0; i < 10; i++)
      routes[`http://registry.test/node9-canary-p${i}`] = () => npmDoc('1.0.0');
    const r = await runPackageCheck(...bash(`npm i ${pkgs}`), CFG);
    const capped = r.misses.filter((m) => m.includes('node9-canary-p10'));
    expect(capped.length).toBeGreaterThan(0);
    expect(capped[0]).toContain('per-command network cap');
    expect(capped[0]).not.toContain('online fallback off');
  });
});

describe('registry lookup URL', () => {
  it('encodes every slash of a package name, not only the first', async () => {
    routes['http://registry.test/@scope%2Fpkg'] = () => npmDoc('1.0.0');
    routes['http://registry.test/@scope%2Fpkg%2F..%2Fother'] = () => npmDoc('1.0.0');
    await registryInfo('npm', '@scope/pkg', undefined, 48 * 3_600_000);
    await registryInfo('npm', '@scope/pkg/../other', undefined, 48 * 3_600_000);
    expect(calls).toEqual([
      'http://registry.test/@scope%2Fpkg',
      'http://registry.test/@scope%2Fpkg%2F..%2Fother',
    ]);
  });
});

// Design 2.1: one knob per outcome. Each one drops only its own finding.
describe('runPackageCheck — newPackage / installScript knobs', () => {
  function youngWithScript() {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-both'] = () =>
      npmDoc('1.0.0', {
        installScript: true,
        modified: new Date(Date.now() - 3 * 3_600_000).toISOString(),
      });
  }
  it('both on: two findings', async () => {
    youngWithScript();
    const r = await runPackageCheck(...bash('npm i node9-canary-both'), CFG);
    expect(r.findings.map((f) => f.kind).sort()).toEqual(['install-script', 'new']);
  });
  it('newPackage off: only the install-script finding', async () => {
    youngWithScript();
    const r = await runPackageCheck(...bash('npm i node9-canary-both'), {
      ...CFG,
      newPackage: 'off',
    });
    expect(r.findings.map((f) => f.kind)).toEqual(['install-script']);
  });
  it('installScript off: only the age finding', async () => {
    youngWithScript();
    const r = await runPackageCheck(...bash('npm i node9-canary-both'), {
      ...CFG,
      installScript: 'off',
    });
    expect(r.findings.map((f) => f.kind)).toEqual(['new']);
  });
  it('both off: no registry call at all', async () => {
    youngWithScript();
    const r = await runPackageCheck(...bash('npm i node9-canary-both'), {
      ...CFG,
      newPackage: 'off',
      installScript: 'off',
    });
    expect(r.verdict).toBe('allow');
    expect(calls.filter((c) => c.includes('registry.test'))).toEqual([]);
  });
});

// ── Design 2.2: npx runs the copy in node_modules ───────────────────────────
import { resolveInstalled } from '../local-resolve';

function projectWith(pkgs: Record<string, string>): string {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-npx-'));
  for (const [name, version] of Object.entries(pkgs)) {
    const dir = path.join(project, 'node_modules', ...name.split('/'));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version }));
  }
  return project;
}

describe('resolveInstalled', () => {
  it('finds a package in node_modules, walking up from a subdirectory, scopes included', () => {
    const project = projectWith({ eslint: '9.1.0', '@types/node': '22.1.0' });
    const deep = path.join(project, 'src', 'pages');
    fs.mkdirSync(deep, { recursive: true });
    expect(resolveInstalled('eslint', deep)?.version).toBe('9.1.0');
    expect(resolveInstalled('@types/node', deep)?.version).toBe('22.1.0');
    expect(resolveInstalled('missing-pkg', deep)).toBeNull();
    fs.rmSync(project, { recursive: true, force: true });
  });
  it('resolves nothing for a relative or missing cwd, or a name with a path in it', () => {
    expect(resolveInstalled('eslint', undefined)).toBeNull();
    expect(resolveInstalled('eslint', 'relative/dir')).toBeNull();
    expect(resolveInstalled('../x', os.tmpdir())).toBeNull();
  });
});

describe('runPackageCheck — npx with an installed copy', () => {
  let project: string;
  beforeEach(() => {
    project = projectWith({ eslint: '9.1.0' });
  });
  afterEach(() => fs.rmSync(project, { recursive: true, force: true }));

  it('T1: allows and makes no network call', async () => {
    indexWith('npm', 'node9-canary-other', []);
    const r = await runPackageCheck(...bash('npx eslint src/'), CFG, project);
    expect(r.verdict).toBe('allow');
    expect(calls).toEqual([]);
  });
  it('T2: an installed version the index covers still blocks, saying "installed"', async () => {
    indexWith('npm', 'eslint', [{ id: 'MAL-0000-0009', versions: ['9.1.0'] }]);
    const r = await runPackageCheck(...bash('npx eslint .'), CFG, project);
    expect(r.verdict).toBe('block');
    expect(r.reason).toContain('MAL-0000-0009');
    expect(r.reason).toContain('installed');
    expect(calls).toEqual([]);
  });
  it('T3: with no node_modules the registry is asked as before', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/eslint'] = () => npmDoc('10.0.0');
    const r = await runPackageCheck(...bash('npx eslint .'), CFG, os.tmpdir());
    expect(r.verdict).toBe('allow');
    expect(calls).toEqual(['http://registry.test/eslint']);
  });
  it('npx with a tag or a range is a download, not the local copy', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/eslint'] = () => npmDoc('10.0.0');
    await runPackageCheck(...bash('npx eslint@next .'), CFG, project);
    await runPackageCheck(...bash('npx eslint@^10 .'), CFG, project);
    expect(calls.filter((c) => c.endsWith('/eslint'))).toHaveLength(2);
  });
  it('T5: pnpm dlx and a pinned npx version always go to the registry', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/eslint'] = () => npmDoc('10.0.0');
    await runPackageCheck(...bash('pnpm dlx eslint .'), CFG, project);
    await runPackageCheck(...bash('npx eslint@10.0.0 .'), CFG, project);
    expect(calls.filter((c) => c.endsWith('/eslint'))).toHaveLength(2);
  });
  it('an unreadable local index records a miss and allows', async () => {
    const r = await runPackageCheck(...bash('npx eslint .'), CFG, project);
    expect(r.verdict).toBe('allow');
    expect(r.misses.some((m) => m.includes('installed copy'))).toBe(true);
  });
});

// ── Design 2.3: age from the version's own publish time ─────────────────────
describe('runPackageCheck — npm age is version-true', () => {
  const FRESH = new Date(Date.now() - 3 * 3_600_000).toISOString();
  const ninetyDays = new Date(Date.now() - 90 * 24 * 3_600_000).toISOString();
  const isAbbrev = (init?: RequestInit) =>
    String((init?.headers as Record<string, string> | undefined)?.Accept ?? '').includes(
      'install-v1'
    );

  it('T6: a prerelease moved `modified`, but latest is old → no age finding', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-stable'] = (init) =>
      isAbbrev(init)
        ? npmDoc('2.0.0', { modified: FRESH })
        : json({ time: { '2.0.0': ninetyDays, '3.0.0-beta.1': FRESH } });
    const r = await runPackageCheck(...bash('npm i node9-canary-stable'), CFG);
    expect(r.verdict).toBe('allow');
    expect(calls.filter((c) => c.endsWith('node9-canary-stable'))).toHaveLength(2);
  });
  it('a genuinely new latest is still a finding', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-young'] = (init) =>
      isAbbrev(init) ? npmDoc('2.0.0', { modified: FRESH }) : json({ time: { '2.0.0': FRESH } });
    const r = await runPackageCheck(...bash('npm i node9-canary-young'), CFG);
    expect(r.findings.map((f) => f.kind)).toEqual(['new']);
  });
  it('an old `modified` needs no second request', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-old'] = () => npmDoc('1.0.0');
    await runPackageCheck(...bash('npm i node9-canary-old'), CFG);
    expect(calls).toHaveLength(1);
  });
  it('newPackage off: the full document is never fetched', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-fresh'] = (init) =>
      isAbbrev(init) ? npmDoc('2.0.0', { modified: FRESH }) : json({ time: { '2.0.0': FRESH } });
    const r = await runPackageCheck(...bash('npm i node9-canary-fresh'), {
      ...CFG,
      newPackage: 'off',
    });
    expect(r.verdict).toBe('allow');
    expect(calls).toHaveLength(1);
  });
  it('T7: full document over the cap → the finding stays and a miss says why', async () => {
    indexWith('npm', 'node9-canary-other', []);
    routes['http://registry.test/node9-canary-big'] = (init) =>
      isAbbrev(init)
        ? npmDoc('2.0.0', { modified: FRESH })
        : new Response('{}', {
            status: 200,
            headers: { 'content-length': String(5 * 1024 * 1024) },
          });
    const r = await runPackageCheck(...bash('npm i node9-canary-big'), CFG);
    expect(r.findings.map((f) => f.kind)).toEqual(['new']);
    expect(r.misses.some((m) => m.includes('age from the package modified time'))).toBe(true);
  });
});

describe('package resolution regressions', () => {
  let project: string;
  beforeEach(() => {
    project = projectWith({ eslint: '9.1.0' });
  });
  afterEach(() => fs.rmSync(project, { recursive: true, force: true }));

  it.each(['npm install eslint', 'pnpm dlx eslint', 'npx eslint@next'])(
    'checks a later download: %s',
    async (download) => {
      indexWith('npm', 'eslint', [{ id: 'MAL-TEST-DOWNLOAD', versions: ['10.0.0'] }]);
      routes['http://registry.test/eslint'] = () =>
        json({
          modified: OLD,
          'dist-tags': { latest: '10.0.0', next: '10.0.0' },
          versions: { '10.0.0': {} },
        });
      const r = await runPackageCheck(...bash(`npx eslint . && ${download}`), CFG, project);
      expect(r.verdict).toBe('block');
      expect(r.reason).toContain('MAL-TEST-DOWNLOAD');
    }
  );

  it('checks the installed version after a literal directory change', async () => {
    const app = path.join(project, 'app', 'node_modules', 'eslint');
    fs.mkdirSync(app, { recursive: true });
    fs.writeFileSync(
      path.join(app, 'package.json'),
      JSON.stringify({ name: 'eslint', version: '10.0.0' })
    );
    indexWith('npm', 'eslint', [{ id: 'MAL-TEST-CWD', versions: ['10.0.0'] }]);
    const r = await runPackageCheck(...bash('cd app && npx eslint .'), CFG, project);
    expect(r.verdict).toBe('block');
    expect(r.reason).toContain('MAL-TEST-CWD');
    expect(calls).toEqual([]);
  });

  it('does not use the original directory for workspace or prefix overrides', async () => {
    indexWith('npm', 'eslint', [{ id: 'MAL-TEST-REMOTE', versions: ['10.0.0'] }]);
    routes['http://registry.test/eslint'] = () => npmDoc('10.0.0');
    const r = await runPackageCheck(...bash('npm --prefix /other exec eslint'), CFG, project);
    expect(r.verdict).toBe('block');
    expect(calls).not.toEqual([]);
  });

  it('uses an exact matching installed version without a registry call', async () => {
    indexWith('npm', 'node9-canary-other', []);
    const r = await runPackageCheck(...bash('npx eslint@9.1.0 .'), CFG, project);
    expect(r.verdict).toBe('allow');
    expect(calls).toEqual([]);
  });

  it.each(['next', '^10.0.0'])('checks the version selected by %s, not latest', async (spec) => {
    indexWith('npm', 'eslint', [{ id: 'MAL-TEST-SPEC', versions: ['10.1.0'] }]);
    routes['http://registry.test/eslint'] = () =>
      json({
        modified: OLD,
        'dist-tags': { latest: '9.1.0', next: '10.1.0' },
        versions: { '9.1.0': {}, '10.1.0': {} },
      });
    const r = await runPackageCheck(...bash(`npx eslint@${spec}`), CFG, project);
    expect(r.verdict).toBe('block');
    expect(r.findings[0].version).toBe('10.1.0');
  });
});

it('resolves a bare npm alias to the target package latest', async () => {
  indexWith('npm', 'eslint', [{ id: 'MAL-TEST-ALIAS', versions: ['10.0.0'] }]);
  routes['http://registry.test/eslint'] = () => npmDoc('10.0.0');
  const result = await runPackageCheck(...bash('npm install lint@npm:eslint'), CFG);
  expect(result.verdict).toBe('block');
  expect(result.findings[0].version).toBe('10.0.0');
});

describe('runPackageCheck — beyond npm and PyPI (node9Firewall#360)', () => {
  const osvAnswer = (ids: string[][]) => () =>
    json({ results: ids.map((list) => ({ vulns: list.map((id) => ({ id })) })) });

  it('a pinned RubyGems version OSV online marks malicious blocks; no registry is asked', async () => {
    routes['http://osv.test/v1/querybatch'] = osvAnswer([['MAL-0000-0101']]);
    const r = await runPackageCheck(...bash('gem install example-mal-gem -v 1.0.0'), CFG);
    expect(r.verdict).toBe('block');
    expect(r.reason).toContain('RubyGems package "example-mal-gem@1.0.0"');
    expect(r.reason).toContain('MAL-0000-0101');
    expect(calls).toEqual(['http://osv.test/v1/querybatch']);
  });

  it('unpinned with a malicious record online: review, as an unpinned npm install is', async () => {
    routes['http://osv.test/v1/querybatch'] = osvAnswer([['MAL-0000-0102']]);
    const r = await runPackageCheck(...bash('dotnet add package Example.Mal'), CFG);
    expect(r.verdict).toBe('review');
    expect(r.reason).toContain('NuGet package "Example.Mal" has known malicious versions');
    expect(r.misses).toEqual([]);
  });

  it('the online query carries the OSV ecosystem name and the name as written', async () => {
    let body = '';
    routes['http://osv.test/v1/querybatch'] = (init) => {
      body = String(init?.body);
      return osvAnswer([[]])();
    };
    await runPackageCheck(...bash('code --install-extension Acme.Widget@1.2.3'), CFG);
    expect(JSON.parse(body)).toEqual({
      queries: [{ package: { name: 'Acme.Widget', ecosystem: 'VSCode' }, version: '1.2.3' }],
    });
  });

  it('a Go package path is looked up by every module prefix, longest first', async () => {
    let body = '';
    routes['http://osv.test/v1/querybatch'] = (init) => {
      body = String(init?.body);
      return osvAnswer([[], [], ['MAL-0000-0103'], []])();
    };
    const r = await runPackageCheck(
      ...bash('go install example.test/owner/mod/cmd/tool@latest'),
      CFG
    );
    expect(
      JSON.parse(body).queries.map((q: { package: { name: string } }) => q.package.name)
    ).toEqual([
      'example.test/owner/mod/cmd/tool',
      'example.test/owner/mod/cmd',
      'example.test/owner/mod',
      'example.test/owner',
    ]);
    expect(r.verdict).toBe('review');
    expect(r.reason).toContain('MAL-0000-0103');
  });

  it('a Go module the local index marks malicious in every version blocks a sub-package install', async () => {
    indexWith('Go', 'example.test/owner/mod', [{ id: 'MAL-0000-0104', all: true }]);
    const r = await runPackageCheck(...bash('go get example.test/owner/mod/sub@v1.0.0'), CFG);
    expect(r.verdict).toBe('block');
    expect(r.reason).toContain('Go module "example.test/owner/mod/sub@1.0.0"');
    expect(calls).toEqual([]);
  });

  it('a clean fresh crates.io index allows without any network call', async () => {
    indexWith('crates.io', 'example-other', [{ id: 'MAL-0000-0105', all: true }]);
    const r = await runPackageCheck(...bash('cargo add example-clean@1.0.0'), CFG);
    expect(r.verdict).toBe('allow');
    expect(calls).toEqual([]);
    expect(r.misses).toEqual([]);
  });

  it('crates.io names match across - and _', async () => {
    indexWith('crates.io', 'example-mal-crate', [{ id: 'MAL-0000-0106', versions: ['0.1.0'] }]);
    const r = await runPackageCheck(...bash('cargo add example_mal_crate@0.1.0'), CFG);
    expect(r.verdict).toBe('block');
  });

  it('OSV online down: allow with a miss, and still no registry request', async () => {
    routes['http://osv.test/v1/querybatch'] = () => json({}, 503);
    const r = await runPackageCheck(...bash('composer require acme/widget'), CFG);
    expect(r.verdict).toBe('allow');
    expect(r.misses.join(' ')).toContain('Packagist package "acme/widget"');
    expect(calls).toEqual(['http://osv.test/v1/querybatch']);
  });
});

describe('runPackageCheck — abbreviated document over the size cap (fw#372 A10)', () => {
  const tooLarge = () =>
    new Response('{}', {
      status: 200,
      headers: { 'content-type': 'application/json', 'content-length': String(3 * 1024 * 1024) },
    });
  it('resolves the version from the version document, so a record for other versions is not a block', async () => {
    indexWith('npm', 'node9-canary-big', [{ id: 'MAL-0000-0002', versions: ['1.0.0'] }]);
    routes['http://registry.test/node9-canary-big'] = tooLarge;
    routes['http://registry.test/node9-canary-big/latest'] = () =>
      json({ name: 'node9-canary-big', version: '2.0.0', scripts: { test: 'vitest' } });
    const r = await runPackageCheck(...bash('npm i node9-canary-big'), {
      ...CFG,
      newPackage: 'off',
    });
    expect(r.verdict).toBe('allow');
    expect(r.misses.join('\n')).toMatch(/size cap/);
    expect(calls).toContain('http://registry.test/node9-canary-big/latest');
  });
  it('an install script in the version document is still a finding', async () => {
    routes['http://registry.test/node9-canary-big'] = tooLarge;
    routes['http://registry.test/node9-canary-big/latest'] = () =>
      json({
        name: 'node9-canary-big',
        version: '2.0.0',
        scripts: { postinstall: 'node setup.js' },
      });
    const r = await runPackageCheck(...bash('npm i node9-canary-big'), {
      ...CFG,
      newPackage: 'off',
    });
    expect(r.verdict).toBe('review');
    expect(r.findings.map((f) => f.kind)).toContain('install-script');
  });
  it('a range that latest does not satisfy claims no version, so a record keeps its review (review finding)', async () => {
    indexWith('npm', 'node9-canary-big', [{ id: 'MAL-0000-0003', versions: ['1.4.1'] }]);
    routes['http://registry.test/node9-canary-big'] = tooLarge;
    routes['http://registry.test/node9-canary-big/latest'] = () =>
      json({ name: 'node9-canary-big', version: '3.0.0', scripts: {} });
    const r = await runPackageCheck(...bash('npm i node9-canary-big@^1.2.0'), {
      ...CFG,
      newPackage: 'off',
      installScript: 'off',
    });
    expect(r.verdict).toBe('review');
    expect(r.findings[0].kind).toBe('malicious-unpinned');
  });
  it('a pinned version reads its own document', async () => {
    routes['http://registry.test/node9-canary-big'] = tooLarge;
    routes['http://registry.test/node9-canary-big/1.5.0'] = () =>
      json({ name: 'node9-canary-big', version: '1.5.0', scripts: {} });
    const r = await runPackageCheck(...bash('npm i node9-canary-big@1.5.0'), {
      ...CFG,
      newPackage: 'off',
    });
    expect(r.verdict).toBe('allow');
    expect(calls).toContain('http://registry.test/node9-canary-big/1.5.0');
  });
});

describe('runPackageCheck — the release before this one (node9Firewall#385)', () => {
  const FRESH = new Date(Date.now() - 3 * 3_600_000).toISOString();
  const isAbbrev = (init?: RequestInit) =>
    String((init?.headers as Record<string, string> | undefined)?.Accept ?? '').includes(
      'install-v1'
    );
  type V = { script?: boolean; prov?: boolean };
  const prov = (name: string, v: string) => ({
    url: `http://registry.test/-/npm/v1/attestations/${name}@${v}`,
    provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
  });
  /** An abbreviated document with a version list, newest = latest. */
  function npmHistory(name: string, versions: Record<string, V>, modified = OLD) {
    const keys = Object.keys(versions);
    return json({
      name,
      modified,
      'dist-tags': { latest: keys[keys.length - 1] },
      versions: Object.fromEntries(
        keys.map((v) => [
          v,
          {
            hasInstallScript: versions[v].script || undefined,
            dist: versions[v].prov ? { attestations: prov(name, v) } : {},
          },
        ])
      ),
    });
  }
  /** An npm attestation document whose SLSA provenance names `repo`. */
  function attestation(repo: string) {
    const statement = {
      predicate: { buildDefinition: { externalParameters: { workflow: { repository: repo } } } },
    };
    return json({
      attestations: [
        { predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1' },
        {
          predicateType: 'https://slsa.dev/provenance/v1',
          bundle: {
            dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString('base64') },
          },
        },
      ],
    });
  }
  const att = (name: string, v: string) =>
    `http://registry.test/-/npm/v1/attestations/${name}@${v}`;

  describe('install scripts', () => {
    it('a script the previous release also ran is no finding (esbuild, bcrypt)', async () => {
      indexWith('npm', 'node9-canary-other', []);
      routes['http://registry.test/node9-canary-native'] = () =>
        npmHistory('node9-canary-native', { '1.0.0': { script: true }, '1.1.0': { script: true } });
      const r = await runPackageCheck(...bash('npm i node9-canary-native'), CFG);
      expect(r.verdict).toBe('allow');
      expect(calls).toHaveLength(1);
    });
    it('a script that appears in this release is a finding (the Shai-Hulud shape)', async () => {
      indexWith('npm', 'node9-canary-other', []);
      routes['http://registry.test/node9-canary-native'] = () =>
        npmHistory('node9-canary-native', { '1.0.0': {}, '1.1.0': { script: true } });
      const r = await runPackageCheck(...bash('npm i node9-canary-native'), CFG);
      expect(r.findings.map((f) => f.kind)).toEqual(['install-script']);
    });
    it('a first release with a script is a finding', async () => {
      indexWith('npm', 'node9-canary-other', []);
      routes['http://registry.test/node9-canary-native'] = () =>
        npmHistory('node9-canary-native', { '1.0.0': { script: true } });
      const r = await runPackageCheck(...bash('npm i node9-canary-native'), CFG);
      expect(r.findings.map((f) => f.kind)).toEqual(['install-script']);
    });
    it('a prerelease is not "the release before"', async () => {
      indexWith('npm', 'node9-canary-other', []);
      routes['http://registry.test/node9-canary-native'] = () =>
        npmHistory('node9-canary-native', {
          '1.0.0': {},
          '1.1.0-beta.1': { script: true },
          '1.1.0': { script: true },
        });
      const r = await runPackageCheck(...bash('npm i node9-canary-native'), CFG);
      expect(r.findings.map((f) => f.kind)).toEqual(['install-script']);
    });
  });

  describe('provenance (npm)', () => {
    const young = (versions: Record<string, V>) => (init?: RequestInit) =>
      isAbbrev(init)
        ? npmHistory('node9-canary-ci', versions, FRESH)
        : json({ time: { '2.0.0': FRESH } });

    it('a young release built from the same repository as the one before it passes', async () => {
      indexWith('npm', 'node9-canary-other', []);
      routes['http://registry.test/node9-canary-ci'] = young({
        '1.0.0': { prov: true },
        '2.0.0': { prov: true, script: true },
      });
      routes[att('node9-canary-ci', '2.0.0')] = () => attestation('https://github.com/acme/ci');
      routes[att('node9-canary-ci', '1.0.0')] = () => attestation('https://github.com/Acme/ci.git');
      const r = await runPackageCheck(...bash('npm i node9-canary-ci'), CFG);
      expect(r.verdict).toBe('allow');
      expect(r.findings).toEqual([]);
    });
    it('built from another repository: the findings stay', async () => {
      indexWith('npm', 'node9-canary-other', []);
      routes['http://registry.test/node9-canary-ci'] = young({
        '1.0.0': { prov: true },
        '2.0.0': { prov: true },
      });
      routes[att('node9-canary-ci', '2.0.0')] = () => attestation('https://github.com/evil/fork');
      routes[att('node9-canary-ci', '1.0.0')] = () => attestation('https://github.com/acme/ci');
      const r = await runPackageCheck(...bash('npm i node9-canary-ci'), CFG);
      expect(r.findings.map((f) => f.kind)).toEqual(['new']);
    });
    it('provenance that disappears is a finding, even outside the age window, with no extra request', async () => {
      indexWith('npm', 'node9-canary-other', []);
      routes['http://registry.test/node9-canary-ci'] = () =>
        npmHistory('node9-canary-ci', { '1.0.0': { prov: true }, '1.0.1': {} });
      const r = await runPackageCheck(...bash('npm i node9-canary-ci'), CFG);
      expect(r.verdict).toBe('review');
      expect(r.findings.map((f) => f.kind)).toEqual(['provenance-drop']);
      expect(r.reason).toContain('without the provenance its previous release (1.0.0) had');
      expect(calls).toHaveLength(1);
    });
    it('an unreadable provenance record keeps the findings and records a miss', async () => {
      indexWith('npm', 'node9-canary-other', []);
      routes['http://registry.test/node9-canary-ci'] = young({
        '1.0.0': { prov: true },
        '2.0.0': { prov: true },
      });
      routes[att('node9-canary-ci', '2.0.0')] = () => json({}, 500);
      routes[att('node9-canary-ci', '1.0.0')] = () => attestation('https://github.com/acme/ci');
      const r = await runPackageCheck(...bash('npm i node9-canary-ci'), CFG);
      expect(r.findings.map((f) => f.kind)).toEqual(['new']);
      expect(r.misses.join('\n')).toContain('provenance unreadable');
    });
    it('a known malicious release is blocked whatever its provenance', async () => {
      indexWith('npm', 'node9-canary-ci', [{ id: 'MAL-0000-0009', versions: ['2.0.0'] }]);
      routes['http://registry.test/node9-canary-ci'] = young({
        '1.0.0': { prov: true },
        '2.0.0': { prov: true },
      });
      routes[att('node9-canary-ci', '2.0.0')] = () => attestation('https://github.com/acme/ci');
      routes[att('node9-canary-ci', '1.0.0')] = () => attestation('https://github.com/acme/ci');
      const r = await runPackageCheck(...bash('npm i node9-canary-ci'), CFG);
      expect(r.verdict).toBe('block');
    });
  });

  describe('provenance (PyPI)', () => {
    const recent = new Date(Date.now() - 3_600_000).toISOString();
    const project = (name: string) =>
      json({
        info: { version: '2.0' },
        urls: [{ upload_time_iso_8601: recent, filename: `${name}-2.0.tar.gz` }],
        releases: {
          '1.9': [{ filename: `${name}-1.9.tar.gz` }],
          '2.0rc1': [{ filename: `${name}-2.0rc1.tar.gz` }],
          '2.0': [{ filename: `${name}-2.0.tar.gz` }],
        },
      });
    const integrity = (name: string, v: string) =>
      `http://pypi.test/integrity/${name}/${v}/${name}-${v}.tar.gz/provenance`;
    const bundle = (repository: string) =>
      json({
        version: 1,
        attestation_bundles: [{ publisher: { kind: 'GitHub', repository, workflow: 'r.yml' } }],
      });

    it('a young release uploaded by the same Trusted Publisher repository passes', async () => {
      indexWith('PyPI', 'node9-canary-other', []);
      routes['http://pypi.test/pypi/node9-canary-py/json'] = () => project('node9-canary-py');
      routes[integrity('node9-canary-py', '2.0')] = () => bundle('acme/py');
      routes[integrity('node9-canary-py', '1.9')] = () => bundle('acme/py');
      const r = await runPackageCheck(...bash('pip install node9-canary-py'), CFG);
      expect(r.verdict).toBe('allow');
    });
    it('a pinned install reads the history it needs only because of a finding', async () => {
      indexWith('PyPI', 'node9-canary-other', []);
      routes['http://pypi.test/pypi/node9-canary-py/2.0/json'] = () =>
        json({
          info: { version: '2.0' },
          urls: [{ upload_time_iso_8601: recent, filename: 'node9-canary-py-2.0.tar.gz' }],
        });
      routes['http://pypi.test/pypi/node9-canary-py/json'] = () => project('node9-canary-py');
      routes[integrity('node9-canary-py', '2.0')] = () => bundle('acme/py');
      routes[integrity('node9-canary-py', '1.9')] = () => bundle('acme/py');
      const r = await runPackageCheck(...bash('pip install node9-canary-py==2.0'), CFG);
      expect(r.verdict).toBe('allow');
      expect(calls).toContain('http://pypi.test/pypi/node9-canary-py/json');
    });
    it('no provenance where the previous release had it: a finding of its own', async () => {
      indexWith('PyPI', 'node9-canary-other', []);
      routes['http://pypi.test/pypi/node9-canary-py/json'] = () => project('node9-canary-py');
      routes[integrity('node9-canary-py', '2.0')] = () => new Response('', { status: 404 });
      routes[integrity('node9-canary-py', '1.9')] = () => bundle('acme/py');
      const r = await runPackageCheck(...bash('pip install node9-canary-py'), CFG);
      expect(r.findings.map((f) => f.kind)).toEqual(['new', 'provenance-drop']);
    });
    it('neither release has provenance: the age finding stays', async () => {
      indexWith('PyPI', 'node9-canary-other', []);
      routes['http://pypi.test/pypi/node9-canary-py/json'] = () => project('node9-canary-py');
      routes[integrity('node9-canary-py', '2.0')] = () => new Response('', { status: 404 });
      routes[integrity('node9-canary-py', '1.9')] = () => new Response('', { status: 404 });
      const r = await runPackageCheck(...bash('pip install node9-canary-py'), CFG);
      expect(r.findings.map((f) => f.kind)).toEqual(['new']);
    });
  });
});
