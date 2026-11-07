/**
 * node9Firewall#385 wave 3 on the shipped binary: `node9 check` gets a Claude
 * Code PreToolUse payload for an npm install; a local HTTP server stands in
 * for the npm registry (NODE9_TESTING=1 honours the URL override) and the
 * downloads API; the OSV index in a temp HOME is empty.
 *
 *   - a name the registry does not have asks at Standard and Strict, not at
 *     Soft; one letter off a popular name, the reason names that name
 *   - a release three hours old of a package over a year old that released
 *     within 180 days passes at Standard and asks at Strict (A3, option b)
 *
 * Package names are canaries, not real packages. Requirements: `npm run
 * build` first (dist/cli.js).
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { spawn } from 'child_process';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';
import { keySafeEnv } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const itCli = it.skipIf(!fs.existsSync(CLI));

const STEADY = 'node9-canary-steady';
const DAY = 86_400_000;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

let home: string;
let registry: http.Server;
let registryUrl: string;

function writeEmptyIndex(): void {
  const dir = path.join(home, '.node9', 'osv', 'npm');
  fs.mkdirSync(path.join(dir, 'shards'), { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'meta.json'),
    JSON.stringify({
      syncedAt: new Date().toISOString(),
      lastModifiedMs: 0,
      records: 0,
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
    session_id: 'pkg-check-wave3-it',
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
        NODE9_NPM_DOWNLOADS_URL: registryUrl,
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

function verdict(r: CheckResult): { decision: string; reason: string } {
  if (!r.stdout.trim()) return { decision: 'allow', reason: '' };
  const out = JSON.parse(r.stdout) as {
    hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string };
  };
  return {
    decision: out.hookSpecificOutput?.permissionDecision ?? 'allow',
    reason: out.hookSpecificOutput?.permissionDecisionReason ?? '',
  };
}

beforeAll(async () => {
  registry = http.createServer((req, res) => {
    const json = (body: unknown) =>
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    if (req.url === `/${STEADY}`) {
      const abbreviated = String(req.headers.accept ?? '').includes('install-v1');
      if (abbreviated) {
        json({
          name: STEADY,
          modified: ago(3 * 3_600_000),
          'dist-tags': { latest: '1.1.0' },
          versions: { '1.0.0': {}, '1.1.0': {} },
        });
      } else {
        json({
          time: { created: ago(900 * DAY), '1.0.0': ago(20 * DAY), '1.1.0': ago(3 * 3_600_000) },
        });
      }
      return;
    }
    // Every other name, and every downloads lookup: not found.
    res.writeHead(404, { 'content-type': 'application/json' }).end('{"error":"Not found"}');
  });
  await new Promise<void>((resolve) => registry.listen(0, '127.0.0.1', resolve));
  registryUrl = `http://127.0.0.1:${(registry.address() as AddressInfo).port}`;
});
afterAll(async () => {
  await new Promise<void>((resolve) => registry.close(() => resolve()));
});

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-pkgwave3-it-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  writeEmptyIndex();
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('node9 check — names the registry does not have (node9Firewall#385 wave 3)', () => {
  for (const mode of ['standard', 'strict']) {
    itCli(`${mode}: an invented name asks, and says the registry has no such package`, async () => {
      const r = await check('npm install node9-canary-nowhere', mode);
      expect(r.status).toBe(0);
      const v = verdict(r);
      expect(v.decision).toBe('ask');
      expect(v.reason).toContain('"node9-canary-nowhere" does not exist on npm');
    });
  }
  itCli('soft: the signal is off, so the install is allowed', async () => {
    const r = await check('npm install node9-canary-nowhere', 'soft');
    expect(r.status).toBe(0);
    expect(verdict(r).decision).toBe('allow');
  });
  itCli('standard: one letter off a popular name, the reason names it', async () => {
    const r = await check('npm install reqeust', 'standard');
    expect(r.status).toBe(0);
    const v = verdict(r);
    expect(v.decision).toBe('ask');
    expect(v.reason).toContain(
      '"reqeust" looks like "request" (one letter off) and does not exist on npm'
    );
  });
});

describe('node9 check — a young release of an established package (A3, option b)', () => {
  itCli("standard: the release is the package's cadence, allowed", async () => {
    const r = await check(`npm install ${STEADY}`, 'standard');
    expect(r.status).toBe(0);
    expect(verdict(r).decision).toBe('allow');
  });
  itCli('strict: the same release asks for its age', async () => {
    const r = await check(`npm install ${STEADY}`, 'strict');
    expect(r.status).toBe(0);
    const v = verdict(r);
    expect(v.decision).toBe('ask');
    expect(v.reason).toMatch(/published 3h ago/);
  });
});
