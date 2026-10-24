/**
 * node9Firewall#385 on the shipped binary: `node9 check` for an npm install,
 * against a local HTTP registry (NODE9_NPM_REGISTRY_URL is honoured under
 * NODE9_TESTING=1 only). An install script the previous release also ran
 * passes; one that appears in this release asks; a young release built from
 * the same repository as the one before it passes; a release that lost its
 * provenance asks.
 *
 * Package names and repositories are canaries. Requirements: `npm run build`.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { spawn } from 'child_process';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';
import { keySafeEnv } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const itCli = it.skipIf(!fs.existsSync(CLI));
const OLD = '2020-01-01T00:00:00Z';
const FRESH = new Date(Date.now() - 3 * 3_600_000).toISOString();

let server: http.Server;
let base: string;
let docs: Record<string, unknown>;
let home: string;

type V = { script?: boolean; prov?: boolean };
function abbreviated(name: string, versions: Record<string, V>, modified = OLD) {
  const keys = Object.keys(versions);
  return {
    name,
    modified,
    'dist-tags': { latest: keys[keys.length - 1] },
    versions: Object.fromEntries(
      keys.map((v) => [
        v,
        {
          hasInstallScript: versions[v].script || undefined,
          dist: versions[v].prov
            ? { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } }
            : {},
        },
      ])
    ),
  };
}
function attestation(repo: string) {
  const statement = {
    predicate: { buildDefinition: { externalParameters: { workflow: { repository: repo } } } },
  };
  return {
    attestations: [
      {
        predicateType: 'https://slsa.dev/provenance/v1',
        bundle: {
          dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString('base64') },
        },
      },
    ],
  };
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const key = `${req.url}${String(req.headers.accept ?? '').includes('install-v1') ? '#abbrev' : ''}`;
    const body = docs[key] ?? docs[req.url ?? ''];
    if (body === undefined) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

beforeEach(() => {
  docs = {};
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-pkghist-it-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(path.join(home, '.node9', 'config.json'), '{}');
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

function check(
  command: string
): Promise<{ status: number | null; decision: string; reason: string }> {
  const payload = {
    hook_event_name: 'PreToolUse',
    session_id: 'pkg-history-it',
    cwd: home,
    tool_name: 'Bash',
    tool_input: { command },
  };
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [CLI, 'check', '--agent', 'claude', '--ask', JSON.stringify(payload)],
      {
        cwd: home,
        env: keySafeEnv({
          HOME: home,
          USERPROFILE: home,
          NODE9_TESTING: '1',
          NODE9_NO_AUTO_DAEMON: '1',
          NODE9_NPM_REGISTRY_URL: base,
          NODE9_PYPI_URL: undefined,
          NODE9_OSV_API_URL: undefined,
        }),
      }
    );
    let out = '';
    child.stdout.on('data', (d) => (out += String(d)));
    child.on('error', reject);
    child.on('close', (status) => {
      const h = (out.trim() ? JSON.parse(out) : {}).hookSpecificOutput ?? {};
      resolve({
        status,
        decision: String(h.permissionDecision ?? 'allow'),
        reason: String(h.permissionDecisionReason ?? ''),
      });
    });
  });
}

describe('node9 check: the release before this one (fw#385)', () => {
  itCli('an install script the previous release also ran passes', async () => {
    docs['/node9-canary-native#abbrev'] = abbreviated('node9-canary-native', {
      '1.0.0': { script: true },
      '1.1.0': { script: true },
    });
    expect((await check('npm install node9-canary-native')).decision).toBe('allow');
  });

  itCli('an install script that appears in this release asks', async () => {
    docs['/node9-canary-native#abbrev'] = abbreviated('node9-canary-native', {
      '1.0.0': {},
      '1.1.0': { script: true },
    });
    const r = await check('npm install node9-canary-native');
    expect(r.decision).toBe('ask');
    expect(r.reason).toContain('install script');
  });

  itCli('a young release built from the same repository as the one before it passes', async () => {
    docs['/node9-canary-ci#abbrev'] = abbreviated(
      'node9-canary-ci',
      { '1.0.0': { prov: true }, '2.0.0': { prov: true } },
      FRESH
    );
    docs['/node9-canary-ci'] = { time: { '2.0.0': FRESH } };
    docs['/-/npm/v1/attestations/node9-canary-ci@2.0.0'] = attestation(
      'https://github.com/acme/ci'
    );
    docs['/-/npm/v1/attestations/node9-canary-ci@1.0.0'] = attestation(
      'https://github.com/acme/ci'
    );
    expect((await check('npm install node9-canary-ci')).decision).toBe('allow');
  });

  itCli('a release that lost its provenance asks, whatever its age', async () => {
    docs['/node9-canary-ci#abbrev'] = abbreviated('node9-canary-ci', {
      '1.0.0': { prov: true },
      '1.0.1': {},
    });
    const r = await check('npm install node9-canary-ci');
    expect(r.decision).toBe('ask');
    expect(r.reason).toContain('without the provenance');
  });
});
