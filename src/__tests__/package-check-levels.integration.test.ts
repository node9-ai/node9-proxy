/**
 * node9Firewall#412: the package check at every protection level, on the
 * shipped binary. `node9 check` gets a Claude Code PreToolUse payload for an
 * npm install; the OSV index lives in a temp HOME and a local HTTP server
 * stands in for the npm registry (NODE9_TESTING=1 honours the URL override).
 *
 * The package had a malicious version once (1.0.0) and its latest (2.0.0) is
 * clean. An unpinned install gets the clean latest at every level; Soft used
 * to skip the registry with its signals off and hold it while Standard
 * allowed it. A pinned install of the malicious version blocks at every level.
 *
 * Package names and advisory ids are canaries, not real packages.
 * Requirements: `npm run build` first (dist/cli.js).
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { spawn } from 'child_process';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';
import { createHash } from 'crypto';
import { keySafeEnv } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const itCli = it.skipIf(!fs.existsSync(CLI));

const PKG = 'node9-canary-past';
const ADVISORY = 'MAL-0000-0412';

let home: string;
let registry: http.Server;
let registryUrl: string;
let registryHits: string[];

function writeIndex(name: string, entries: object[]): void {
  const dir = path.join(home, '.node9', 'osv', 'npm');
  const shard = createHash('sha1').update(name).digest('hex').slice(0, 2);
  fs.mkdirSync(path.join(dir, 'shards'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'shards', `${shard}.json`), JSON.stringify({ [name]: entries }));
  fs.writeFileSync(
    path.join(dir, 'meta.json'),
    JSON.stringify({
      syncedAt: new Date().toISOString(),
      lastModifiedMs: 0,
      records: 1,
      mode: 'full',
    })
  );
}

interface CheckResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function check(command: string, mode: string): Promise<CheckResult> {
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ version: '2', mode })
  );
  const payload = {
    hook_event_name: 'PreToolUse',
    session_id: 'pkg-check-levels-it',
    cwd: home,
    tool_name: 'Bash',
    tool_input: { command },
  };
  const tmp = path.join(home, 'tmp');
  fs.mkdirSync(tmp, { recursive: true });
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'check', JSON.stringify(payload)], {
      cwd: home,
      env: keySafeEnv({
        HOME: home,
        USERPROFILE: home,
        TMPDIR: tmp,
        NODE9_TESTING: '1',
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_NPM_REGISTRY_URL: registryUrl,
        NODE9_PYPI_URL: undefined,
        NODE9_OSV_API_URL: undefined,
      }) as NodeJS.ProcessEnv,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    const timer = setTimeout(() => child.kill(), 60000);
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

function decision(r: CheckResult): string {
  if (!r.stdout.trim()) return 'allow';
  const out = JSON.parse(r.stdout) as {
    hookSpecificOutput?: { permissionDecision?: string };
  };
  return out.hookSpecificOutput?.permissionDecision ?? 'allow';
}

beforeAll(async () => {
  registry = http.createServer((req, res) => {
    registryHits.push(req.url ?? '');
    if (req.url !== `/${PKG}`) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' }).end(
      JSON.stringify({
        name: PKG,
        modified: '2020-01-01T00:00:00Z',
        'dist-tags': { latest: '2.0.0' },
        versions: { '1.0.0': {}, '2.0.0': {} },
      })
    );
  });
  await new Promise<void>((resolve) => registry.listen(0, '127.0.0.1', resolve));
  registryUrl = `http://127.0.0.1:${(registry.address() as AddressInfo).port}`;
});
afterAll(async () => {
  await new Promise<void>((resolve) => registry.close(() => resolve()));
});

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-pkglevels-it-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  registryHits = [];
  writeIndex(PKG, [{ id: ADVISORY, versions: ['1.0.0'] }]);
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('node9 check — package check at every level (node9Firewall#412)', () => {
  for (const mode of ['soft', 'standard', 'strict']) {
    itCli(`${mode}: an unpinned install whose latest is clean is allowed`, async () => {
      const r = await check(`npm install ${PKG}`, mode);
      expect(r.status).toBe(0);
      expect(decision(r)).toBe('allow');
      expect(r.stdout).not.toContain(ADVISORY);
      expect(registryHits).toContain(`/${PKG}`);
    });

    itCli(`${mode}: a pinned install of the malicious version is blocked`, async () => {
      const r = await check(`npm install ${PKG}@1.0.0`, mode);
      expect(r.status).toBe(2);
      expect(decision(r)).toBe('deny');
      expect(r.stdout).toContain(ADVISORY);
    });
  }
});
