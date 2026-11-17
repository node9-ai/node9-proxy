// fw#481 A1: packages the agent surfaces name (collection, offline) and the registry step
// (stubbed fetch keyed by URL, temp HOME so the developer's OSV index is never read).
// Package names are synthetic canaries, not real packages.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { scanTree, addPackageFindings, packageRefsOf, mergeFindings } from '../ci-check';
import { binProvidedBy, textPackageRefs } from '../ci-check/packages';
import { addedDeps, manifestSetOf, readRefManifests, readWorkingManifests } from '../ci-check/deps';
import { checkAddedDeps } from '../ci-check/package-check';
import { diffScans } from '../ci-check/diff';
import { packagesLine } from '../ci-check/render';
import type { RepoTree, ScanResult } from '../ci-check/types';

function tree(files: Record<string, string>): RepoTree {
  return {
    source: 'owner/repo',
    notes: [],
    files: Object.entries(files).map(([p, content]) => ({ path: p, content })),
    paths: Object.keys(files),
    pathsComplete: true,
  };
}
const MCP = (argv: string[]) =>
  JSON.stringify({ mcpServers: { srv: { command: argv[0], args: argv.slice(1) } } }, null, 2);
const HOOK = (cmd: string) =>
  JSON.stringify({
    hooks: { SessionStart: [{ matcher: '*', hooks: [{ type: 'command', command: cmd }] }] },
  });

describe('A1: package references (offline collection)', () => {
  it('reads MCP launches, hook commands and folder-open tasks as auto-run', () => {
    const res = scanTree(
      tree({
        '.mcp.json': MCP(['npx', '-y', 'n9-canary-mcp']),
        '.claude/settings.json': HOOK('npx -y n9-canary-hook@1.2.3 --check'),
        '.vscode/tasks.json': JSON.stringify({
          tasks: [
            { label: 'x', command: 'uvx n9-canary-task', runOptions: { runOn: 'folderOpen' } },
          ],
        }),
      })
    );
    const refs = packageRefsOf(res);
    const got = refs.map((r) => [r.surface, r.ecosystem, r.name, r.version ?? null, r.autoRun]);
    expect(got.sort((a, b) => String(a[2]).localeCompare(String(b[2])))).toEqual([
      ['hook', 'npm', 'n9-canary-hook', '1.2.3', true],
      ['mcp', 'npm', 'n9-canary-mcp', null, true],
      ['task', 'PyPI', 'n9-canary-task', null, true],
    ]);
  });

  it('reads Codex and opencode MCP servers, skips disabled ones', () => {
    const res = scanTree(
      tree({
        '.codex/config.toml':
          '[mcp_servers.a]\ncommand = "npx"\nargs = ["-y", "n9-canary-codex"]\n',
        'opencode.json': JSON.stringify({
          mcp: {
            on: { command: ['npx', '-y', 'n9-canary-oc'] },
            off: { command: ['npx', '-y', 'n9-canary-off'], enabled: false },
          },
        }),
      })
    );
    const names = packageRefsOf(res).map((r) => r.name);
    expect(names).toContain('n9-canary-codex');
    expect(names).toContain('n9-canary-oc');
    expect(names).not.toContain('n9-canary-off');
  });

  it('docs: shell blocks, inline code and Markdown blocks; never prose or other languages', () => {
    const doc = [
      '# Setup',
      'Install pip packages as you like, then run npx tools.', // prose
      '```bash',
      '$ npx n9-canary-block --init',
      'pip install n9-canary-py==1.0',
      '```',
      '```python',
      'os.system("npx n9-canary-python")',
      '```',
      'Run `npx n9-canary-inline` to check.',
      '```markdown',
      '3. Run the script: `npx n9-canary-md`',
      '```',
      '```bash',
      'npm install <package-name>',
      'npm install my-awesome-tool',
      '```',
    ].join('\n');
    const refs = textPackageRefs('CLAUDE.md', doc, 'doc');
    expect(refs.map((r) => [r.name, r.line])).toEqual([
      ['n9-canary-block', 4],
      ['n9-canary-py', 5],
      ['n9-canary-inline', 10],
      ['n9-canary-md', 12],
    ]);
    expect(refs.every((r) => !r.autoRun)).toBe(true);
  });

  it('scripts: shell scripts are read, other languages are not; a hook script is auto-run', () => {
    expect(textPackageRefs('skills/x/run.sh', 'npx n9-canary-sh\n', 'skill-script')).toHaveLength(
      1
    );
    expect(textPackageRefs('skills/x/run.py', '# pip install n9-canary\n', 'skill-script')).toEqual(
      []
    );
    const hook = textPackageRefs(
      '.claude/hooks/h',
      '#!/bin/bash\nnpx n9-canary-h\n',
      'hook-script'
    );
    expect(hook.map((r) => r.autoRun)).toEqual([true]);
  });

  it('a -p after the npx command is the command argument, not a package (engine fix)', () => {
    const refs = textPackageRefs('AGENTS.md', '```\nnpx tsc -p tsconfig.build.json\n```', 'doc');
    expect(refs.map((r) => r.name)).toEqual(['tsc']);
  });

  it('binProvidedBy: the usual package shapes behind a bin name', () => {
    const declared = new Set(['@dotenvx/dotenvx', '@slidev/cli', 'eslint', 'foo-cli']);
    expect(binProvidedBy('dotenvx', declared)).toBe('@dotenvx/dotenvx');
    expect(binProvidedBy('slidev', declared)).toBe('@slidev/cli');
    expect(binProvidedBy('foo', declared)).toBe('foo-cli');
    expect(binProvidedBy('n9-canary', declared)).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------
// The registry step, against stubbed npm / PyPI / OSV.

const OLD = '2020-01-01T00:00:00Z';
let home: string;
let saved: Record<string, string | undefined>;
let routes: Record<string, (init?: RequestInit) => Response>;
let calls: string[];

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const npmPresent = (latest = '1.0.0') =>
  json({ modified: OLD, 'dist-tags': { latest }, versions: { [latest]: {} } });
const npmPlaceholder = () =>
  json({
    modified: OLD,
    'dist-tags': { latest: '0.0.1-security' },
    versions: { '0.0.1-security': {} },
  });
const absent = () => new Response('not found', { status: 404 });
const REG = 'http://registry.test';
const OSV = 'http://osv.test';

/** OSV: MAL- records by name; every other name is clean. */
function osvWith(mal: Record<string, string>) {
  routes[`${OSV}/v1/querybatch`] = (init) => {
    const body = JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] };
    return json({
      results: body.queries.map((q) =>
        mal[q.package.name] ? { vulns: [{ id: mal[q.package.name] }] } : {}
      ),
    });
  };
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-a1-'));
  saved = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    NODE9_TESTING: process.env.NODE9_TESTING,
    NODE9_NPM_REGISTRY_URL: process.env.NODE9_NPM_REGISTRY_URL,
    NODE9_PYPI_URL: process.env.NODE9_PYPI_URL,
    NODE9_OSV_API_URL: process.env.NODE9_OSV_API_URL,
    NODE9_NPM_DOWNLOADS_URL: process.env.NODE9_NPM_DOWNLOADS_URL,
  };
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  process.env.NODE9_TESTING = '1';
  process.env.NODE9_NPM_REGISTRY_URL = REG;
  process.env.NODE9_PYPI_URL = 'http://pypi.test';
  process.env.NODE9_OSV_API_URL = OSV;
  process.env.NODE9_NPM_DOWNLOADS_URL = 'http://downloads.test';
  routes = {};
  calls = [];
  osvWith({});
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    calls.push(String(url));
    const route = routes[String(url)];
    if (!route) return absent();
    return route(init);
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(home, { recursive: true, force: true });
});

const pkg = (r: ScanResult) => r.findings.filter((f) => f.rule.startsWith('CI-3.package-'));

describe('A1: registry step on scan findings', () => {
  it('an unregistered package an MCP config starts: high, counted', async () => {
    const res = await addPackageFindings(
      scanTree(tree({ '.mcp.json': MCP(['npx', '-y', 'n9-canary-absent']) })),
      { cacheDir: null }
    );
    const f = pkg(res);
    expect(f.map((x) => [x.rule, x.severity])).toEqual([['CI-3.package-absent', 'high']]);
    expect(res.worst).toBe('high');
    expect(res.findings.find((x) => x.rule === 'CI-3.package-absent')?.tier).toBe('alert');
    expect(res.packages).toEqual({ names: 1, checked: 1, capped: 0, failed: 0 });
    expect(packagesLine(res)).toMatch(/1 not on the registry/);
  });

  it('the same name in docs only: a review item, never counted', async () => {
    const res = await addPackageFindings(
      scanTree(tree({ 'CLAUDE.md': '```\nnpx n9-canary-absent\n```\n' })),
      { cacheDir: null }
    );
    const f = res.findings.find((x) => x.rule === 'CI-3.package-absent');
    expect(f?.severity).toBe('advisory');
    expect(f?.tier).toBe('review');
    expect(res.worst).toBeNull();
  });

  it('a known malicious package: critical on an auto-run surface, high in a doc', async () => {
    routes[`${REG}/n9-canary-mal`] = () => npmPresent('2.0.0');
    osvWith({ 'n9-canary-mal': 'MAL-0000-0009' });
    const auto = await addPackageFindings(
      scanTree(tree({ '.claude/settings.json': HOOK('npx -y n9-canary-mal') })),
      { cacheDir: null }
    );
    expect(pkg(auto).map((x) => x.severity)).toEqual(['critical']);
    const doc = await addPackageFindings(scanTree(tree({ 'AGENTS.md': '`npx n9-canary-mal`\n' })), {
      cacheDir: null,
    });
    const f = pkg(doc)[0];
    expect([f.severity, f.tier]).toEqual(['high', 'alert']);
    expect(f.signals.join(' ')).toContain('MAL-0000-0009');
  });

  it('a name npm removed as malicious: medium on auto-run, review in a doc', async () => {
    routes[`${REG}/n9-canary-held`] = () => npmPlaceholder();
    const res = await addPackageFindings(
      scanTree(
        tree({
          '.mcp.json': MCP(['npx', '-y', 'n9-canary-held']),
          'docs/skills/x/SKILL.md': '`npx n9-canary-held`\n',
        })
      ),
      { cacheDir: null }
    );
    const f = res.findings.filter((x) => x.rule === 'CI-3.package-removed');
    expect(f.map((x) => [x.file, x.severity])).toEqual([['.mcp.json', 'medium']]);
    expect(f[0].signals.join(' ')).toMatch(/also named in 1 other file/);
  });

  it('a scoped name whose scope has packages is not a finding; an empty scope is', async () => {
    // An org or user that exists answers 200 (even with no public package); nobody: 404.
    routes[`${REG}/-/org/n9owned/package`] = () => json({});
    const res = await addPackageFindings(
      scanTree(
        tree({
          '.mcp.json': JSON.stringify({
            mcpServers: {
              a: { command: 'npx', args: ['-y', '@n9owned/tool'] },
              b: { command: 'npx', args: ['-y', '@n9free/tool'] },
            },
          }),
        })
      ),
      { cacheDir: null }
    );
    expect(pkg(res).map((x) => x.locator)).toEqual(['npm:@n9free/tool']);
  });

  it('a doc running the bin of a declared dependency is not a finding', async () => {
    const res = await addPackageFindings(
      scanTree(
        tree({
          'package.json': JSON.stringify({ devDependencies: { '@n9canary/n9tool': '^1.0.0' } }),
          'CLAUDE.md': '```\nnpx n9tool run\n```\n',
        })
      ),
      { cacheDir: null }
    );
    expect(pkg(res)).toEqual([]);
  });

  it('docs naming one package in twelve files give one review item that lists the others', async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 12; i++) files[`skills/s${i}/SKILL.md`] = '`npx n9-canary-absent`\n';
    const res = await addPackageFindings(scanTree(tree(files)), { cacheDir: null });
    const f = pkg(res);
    expect(f).toHaveLength(1);
    expect(f[0].signals.join(' ')).toMatch(/also named in 11 other file/);
  });

  it('over the network cap: the rest go to the local index only, and the note says so', async () => {
    const res = await addPackageFindings(
      scanTree(
        tree({ 'CLAUDE.md': '```\nnpx n9-canary-a\nnpx n9-canary-b\nnpx n9-canary-c\n```\n' })
      ),
      { cacheDir: null, networkCap: 1 }
    );
    expect(res.packages).toMatchObject({ names: 3, checked: 1, capped: 2 });
    expect(res.notes.join(' ')).toMatch(/over the per-scan limit of 1/);
  });

  it('a registry that fails is a note, never a finding or a clean claim about the package', async () => {
    routes[`${REG}/n9-canary-err`] = () => new Response('boom', { status: 500 });
    const res = await addPackageFindings(
      scanTree(tree({ '.mcp.json': MCP(['npx', '-y', 'n9-canary-err']) })),
      { cacheDir: null }
    );
    expect(pkg(res)).toEqual([]);
    expect(res.notes.join(' ')).toMatch(/lookup failed for 1 package/);
    expect(res.packages?.failed).toBe(1);
  });

  it('a package in a test fixture tree keeps only counted findings', async () => {
    const res = await addPackageFindings(
      scanTree(
        tree({
          'tests/fixtures/x/.mcp.json': MCP(['npx', '-y', 'n9-canary-absent']),
          'tests/fixtures/x/CLAUDE.md': '`npx n9-canary-absent2`\n',
        })
      ),
      { cacheDir: null }
    );
    // a made-up name in a fixture MCP config is not counted (nor listed)
    expect(pkg(res)).toEqual([]);
  });

  it('a known malicious package in a fixture tree still counts', async () => {
    routes[`${REG}/n9-canary-mal`] = () => npmPresent('2.0.0');
    osvWith({ 'n9-canary-mal': 'MAL-0000-0009' });
    const res = await addPackageFindings(
      scanTree(tree({ 'test/fixtures/a/.mcp.json': MCP(['npx', '-y', 'n9-canary-mal']) })),
      { cacheDir: null }
    );
    expect(pkg(res).map((x) => [x.rule, x.severity, x.tier])).toEqual([
      ['CI-3.package-malicious', 'high', 'alert'],
    ]);
  });

  it('a suppression in .node9-ignore.json covers a package finding like any other', async () => {
    const res = await addPackageFindings(
      scanTree(
        tree({
          '.mcp.json': MCP(['npx', '-y', 'n9-canary-absent']),
          '.node9-ignore.json': JSON.stringify([
            {
              rule: 'CI-3.package-absent',
              file: '.mcp.json',
              locator: 'npm:n9-canary-absent',
              reason: 'our own name, published next week',
            },
          ]),
        })
      ),
      { cacheDir: null }
    );
    const f = res.findings.find((x) => x.rule === 'CI-3.package-absent');
    expect(f?.suppressed).toBeTruthy();
    // Only the pin rule (CI-3.mcp-unpinned, medium) still counts.
    expect(res.worst).toBe('medium');
  });

  it('the disk cache answers a second scan without a request', async () => {
    const cacheDir = path.join(home, 'cache');
    routes[`${REG}/n9-canary-ok`] = () => npmPresent();
    const t = () => scanTree(tree({ '.mcp.json': MCP(['npx', '-y', 'n9-canary-ok']) }));
    await addPackageFindings(t(), { cacheDir });
    const before = calls.length;
    await addPackageFindings(t(), { cacheDir });
    expect(calls.length).toBe(before);
  });

  it('an unreachable registry: after five failed names in a row the rest are not asked', async () => {
    for (let i = 0; i < 20; i++)
      routes[`${REG}/n9-canary-down-${i}`] = () => new Response('down', { status: 503 });
    const doc = Array.from({ length: 20 }, (_, i) => `npx n9-canary-down-${i}`).join('\n');
    const res = await addPackageFindings(
      scanTree(tree({ 'CLAUDE.md': '```\n' + doc + '\n```\n' })),
      {
        cacheDir: null,
      }
    );
    const registryCalls = calls.filter((c) => c.startsWith(`${REG}/n9-canary-down-`)).length;
    expect(registryCalls).toBeLessThan(20);
    expect(res.packages?.capped).toBeGreaterThan(0);
  });

  it('no registry endpoint configured: nothing is reported as a failed lookup', async () => {
    delete process.env.NODE9_NPM_REGISTRY_URL;
    const res = await addPackageFindings(
      scanTree(tree({ '.mcp.json': MCP(['npx', '-y', 'n9-canary-any']) })),
      { cacheDir: null }
    );
    expect(res.packages?.failed).toBe(0);
    expect(res.notes.join(' ')).not.toMatch(/lookup failed/);
  });

  it('the result keeps its package references after the step', async () => {
    const res = await addPackageFindings(
      scanTree(tree({ '.mcp.json': MCP(['npx', '-y', 'n9-canary-absent']) })),
      { cacheDir: null }
    );
    expect(packageRefsOf(res).map((r) => r.name)).toEqual(['n9-canary-absent']);
  });

  it('a scan without package references is returned unchanged, with no request', async () => {
    const base = scanTree(tree({ 'README.md': 'hello' }));
    expect(await addPackageFindings(base, { cacheDir: null })).toBe(base);
    expect(calls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------
// PR mode: dependencies a change adds.

describe('A1: dependencies a change adds (PR mode)', () => {
  it('parses package.json, requirements and pyproject; skips paths, git and workspace specs', () => {
    const set = manifestSetOf(
      new Map([
        [
          'package.json',
          JSON.stringify({
            name: 'n9-root',
            dependencies: {
              a: '^1.0.0',
              b: '1.2.3',
              local: 'file:../x',
              ws: 'workspace:*',
              gh: 'owner/repo',
              aliased: 'npm:n9-real@2.0.0',
            },
          }),
        ],
        ['requirements-dev.txt', 'c==1.0\n-r base.txt\n-e .\nD_e.f>=2 # comment\n'],
        [
          'pyproject.toml',
          '[project]\ndependencies = ["g>=1", "h @ https://x/h.whl"]\n[tool.poetry.dependencies]\npython = "^3.11"\ni = "^2"\nj = { path = "../j" }\n',
        ],
      ])
    );
    expect(
      set.deps.map((d) => `${d.ecosystem}:${d.name}${d.version ? '@' + d.version : ''}`)
    ).toEqual([
      'npm:a',
      'npm:b@1.2.3',
      'npm:n9-real@2.0.0',
      'PyPI:c@1.0',
      'PyPI:d-e-f',
      'PyPI:g',
      'PyPI:i',
    ]);
    expect(set.ownNames.has('n9-root')).toBe(true);
  });

  it('the line of an added dependency is inside its section, not an earlier same-named key', () => {
    const content = JSON.stringify(
      { scripts: { lint: 'eslint .' }, dependencies: { lint: '^1.0.0' } },
      null,
      2
    );
    const d = manifestSetOf(new Map([['package.json', content]])).deps[0];
    expect(content.split('\n')[d.line! - 1]).toContain('"lint": "^1.0.0"');
  });

  it('added = head minus base, by name; own workspace packages are not registry ones', () => {
    const base = manifestSetOf(
      new Map([['package.json', JSON.stringify({ dependencies: { a: '^1.0.0' } })]])
    );
    const head = manifestSetOf(
      new Map([
        ['package.json', JSON.stringify({ dependencies: { a: '^2.0.0', b: '^1.0.0' } })],
        ['packages/ui/package.json', JSON.stringify({ name: '@n9/ui' })],
        ['apps/web/package.json', JSON.stringify({ dependencies: { '@n9/ui': '^1.0.0' } })],
      ])
    );
    expect(addedDeps(base, head).map((d) => d.name)).toEqual(['b']);
  });

  it('an added dependency the registry does not know: high; a private registry excuses it', async () => {
    const added = addedDeps(
      manifestSetOf(new Map()),
      manifestSetOf(
        new Map([['package.json', JSON.stringify({ dependencies: { 'n9-invented': '^1.0.0' } })]])
      )
    );
    const r = await checkAddedDeps(
      added,
      { privateNpm: false, privatePy: false },
      { cacheDir: null }
    );
    expect(r.findings.map((f) => [f.rule, f.severity, f.file])).toEqual([
      ['CI-3.dependency-added-absent', 'high', 'package.json'],
    ]);
    const priv = await checkAddedDeps(
      added,
      { privateNpm: true, privatePy: false },
      { cacheDir: null }
    );
    expect(priv.findings).toEqual([]);
  });

  it('an added dependency first published days ago: a review item', async () => {
    routes[`${REG}/n9-fresh`] = () => npmPresent();
    routes[`${REG}/n9-fresh`] = () =>
      json({
        modified: OLD,
        'dist-tags': { latest: '1.0.0' },
        versions: { '1.0.0': {} },
        time: { created: new Date(Date.now() - 2 * 86_400_000).toISOString() },
      });
    const added = addedDeps(
      manifestSetOf(new Map()),
      manifestSetOf(
        new Map([['package.json', JSON.stringify({ dependencies: { 'n9-fresh': '1.0.0' } })]])
      )
    );
    const r = await checkAddedDeps(
      added,
      { privateNpm: false, privatePy: false },
      { cacheDir: null }
    );
    expect(r.findings.map((f) => [f.rule, f.severity])).toEqual([
      ['CI-3.dependency-added-new', 'advisory'],
    ]);
  });

  it('git: reads manifests at the base ref and in the working tree, and the diff calls them new', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-a1-git-'));
    const git = (...a: string[]) =>
      execFileSync('git', ['-C', dir, '-c', 'user.email=t@t', '-c', 'user.name=t', ...a], {
        stdio: 'ignore',
      });
    git('init', '-q');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { a: '^1' } }));
    fs.mkdirSync(path.join(dir, 'node_modules', 'x'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'node_modules', 'x', 'package.json'),
      JSON.stringify({ dependencies: { 'n9-in-node-modules': '1' } })
    );
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules\n');
    git('add', '.');
    git('commit', '-qm', 'base');
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ dependencies: { a: '^1', 'n9-invented': '^1' } })
    );
    const base = readRefManifests(dir, 'HEAD');
    const head = readWorkingManifests(dir);
    expect(base && [...base.keys()]).toEqual(['package.json']);
    expect(head && [...head.keys()].sort()).toEqual(['package.json']);
    const headSet = manifestSetOf(head!);
    const added = addedDeps(manifestSetOf(base!), headSet);
    expect(added.map((d) => d.name)).toEqual(['n9-invented']);
    const dep = await checkAddedDeps(added, headSet, { cacheDir: null });
    const before = scanTree(tree({}));
    const after = mergeFindings(scanTree(tree({})), dep.findings, dep.notes);
    const diff = diffScans(before, after);
    expect(diff.added.map((f) => f.rule)).toEqual(['CI-3.dependency-added-absent']);
    expect(readRefManifests(dir, '--evil')).toBeNull();
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
