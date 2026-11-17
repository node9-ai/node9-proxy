/**
 * fw#481 A1 on the shipped binary: `node9 scan-repo <dir> --base <ref> --json` against a local
 * git repository, with npm and OSV served by a local HTTP server (NODE9_TESTING routes the
 * lookups there; nothing leaves the machine). Package names are synthetic canaries.
 * Requirements: `npm run build` first (dist/cli.js).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, execFileSync } from 'child_process';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const itCli = it.skipIf(!fs.existsSync(CLI));

let server: http.Server;
let base: string;
let hits: string[] = [];
let repo: string;
let home: string;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    hits.push(req.url ?? '');
    if (req.url === '/v1/querybatch') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const q = JSON.parse(body) as { queries: unknown[] };
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ results: q.queries.map(() => ({})) }));
      });
      return;
    }
    // Every package is unknown to this registry, except the one the base already had.
    if (req.url === '/n9-canary-known') {
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          modified: '2020-01-01T00:00:00Z',
          'dist-tags': { latest: '1.0.0' },
          versions: { '1.0.0': {} },
        })
      );
      return;
    }
    res.statusCode = 404;
    res.end('not found');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-a1-home-'));
  repo = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-a1-repo-'));
  const git = (...a: string[]) =>
    execFileSync('git', ['-C', repo, '-c', 'user.email=t@t', '-c', 'user.name=t', ...a], {
      stdio: 'ignore',
    });
  git('init', '-q');
  fs.writeFileSync(
    path.join(repo, 'package.json'),
    JSON.stringify({ dependencies: { 'n9-canary-known': '^1.0.0' } })
  );
  fs.writeFileSync(
    path.join(repo, '.mcp.json'),
    JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['-y', 'n9-canary-mcp-absent'] } } })
  );
  git('add', '.');
  git('commit', '-qm', 'base');
  // The change under review adds one dependency nobody has published.
  fs.writeFileSync(
    path.join(repo, 'package.json'),
    JSON.stringify({
      dependencies: { 'n9-canary-known': '^1.0.0', 'n9-canary-invented': '^1.0.0' },
    })
  );
});

afterAll(() => {
  server.close();
  fs.rmSync(repo, { recursive: true, force: true });
  fs.rmSync(home, { recursive: true, force: true });
});

/** Async spawn: the mock registry runs in this process, so a sync spawn would deadlock it. */
function scan(...extra: string[]): Promise<{ status: number | null; stdout: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'scan-repo', repo, '--json', ...extra], {
      cwd: home,
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        NODE9_TESTING: '1',
        NODE9_NO_TELEMETRY: '1',
        NODE9_NPM_REGISTRY_URL: base,
        NODE9_OSV_API_URL: base,
        NODE9_PYPI_URL: base,
        NODE9_NPM_DOWNLOADS_URL: base,
      },
    });
    let stdout = '';
    child.stdout.on('data', (c) => (stdout += c));
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, stdout }));
  });
}

describe('scan-repo: packages the agent runs and dependencies a change adds', () => {
  itCli('flags both, and only the added dependency is introduced by the change', async () => {
    hits = [];
    const r = await scan('--base', 'HEAD');
    expect(r.status).not.toBeNull();
    const out = JSON.parse(r.stdout);
    const rules = out.findings.map((f: { rule: string }) => f.rule).sort();
    expect(rules).toContain('CI-3.package-absent');
    expect(rules).toContain('CI-3.dependency-added-absent');
    expect(out.diff.added.map((f: { rule: string }) => f.rule)).toEqual([
      'CI-3.dependency-added-absent',
    ]);
    expect(out.packages).toMatchObject({ names: 1, checked: 1, failed: 0 });
    // base and head share one lookup per name
    expect(hits.filter((h) => h === '/n9-canary-mcp-absent')).toHaveLength(1);
  });

  itCli('--no-package-check asks nothing and adds nothing', async () => {
    hits = [];
    const r = await scan('--base', 'HEAD', '--no-package-check');
    const out = JSON.parse(r.stdout);
    expect(out.packages).toBeUndefined();
    expect(
      out.findings.filter((f: { rule: string }) => /^CI-3\.(package|dependency)-/.test(f.rule))
    ).toEqual([]);
    expect(hits).toEqual([]);
  });
});
