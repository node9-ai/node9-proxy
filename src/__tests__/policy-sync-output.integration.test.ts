/**
 * `node9 policy sync` says what changed (node9-proxy#506), through the built
 * CLI: a temp HOME, and a local HTTPS server that answers GET /policies/sync
 * the way the node9 server does (an ETag, and 304 for a matching
 * If-None-Match). The CLI talks https only, so the test makes a certificate
 * with openssl and hands it to the child as an extra CA; where openssl cannot
 * make one the suite is skipped (the comparison itself is covered in
 * policy-change.spec.ts).
 *
 * Requires `npm run build` first (asserts dist/cli.js exists).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFile, spawnSync } from 'child_process';
import fs from 'fs';
import https from 'https';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';
import { keySafeEnv } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
/** What the fake server answers with now. */
let policy: { etag: string; body: Record<string, unknown> };
let server: https.Server;
let port = 0;
let home = '';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-sync-out-'));
const certFile = path.join(tmp, 'cert.pem');
const keyFile = path.join(tmp, 'key.pem');

/** A certificate for 127.0.0.1, or false where this machine's openssl cannot
 *  make one (none installed, no config file, no -addext): the suite is then
 *  skipped, not failed. */
const hasCert = (() => {
  try {
    const made = spawnSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '2',
        '-keyout',
        keyFile,
        '-out',
        certFile,
        '-subj',
        '/CN=127.0.0.1',
        '-addext',
        'subjectAltName=IP:127.0.0.1',
      ],
      { encoding: 'utf-8' }
    );
    return made.status === 0 && fs.existsSync(certFile) && fs.existsSync(keyFile);
  } catch {
    return false;
  }
})();

/** A sync body for a workspace on Audit with the approved list on. */
function body(mode: string, mcp: Record<string, string>): Record<string, unknown> {
  return {
    policies: [],
    panicMode: false,
    shadowMode: false,
    syncIntervalHours: 1,
    workspaceId: 'ws-1',
    shields: [],
    managedConfig: {
      mode,
      addons: { unapproved: 'log', mcp, skills: {}, plugins: {} },
      locked: [],
    },
  };
}

/** Run the CLI without blocking this process: the server above lives in it. */
function sync(): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, 'policy', 'sync'],
      {
        encoding: 'utf-8',
        timeout: 30_000,
        env: keySafeEnv({
          HOME: home,
          USERPROFILE: home,
          NODE_EXTRA_CA_CERTS: certFile,
          NODE9_NO_AUTO_DAEMON: '1',
          NO_COLOR: '1',
          FORCE_COLOR: '0',
        }),
      },
      (error, stdout, stderr) =>
        resolve({
          code: error && typeof error.code === 'number' ? error.code : error ? 1 : 0,
          stdout,
          stderr,
        })
    );
  });
}

describe.skipIf(!hasCert)('node9 policy sync: what changed', () => {
  beforeAll(async () => {
    expect(fs.existsSync(CLI), `${CLI} missing: run npm run build`).toBe(true);
    home = path.join(tmp, 'home');
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });

    server = https.createServer(
      { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) },
      (req, res) => {
        if (req.method !== 'GET' || req.url !== '/api/v1/intercept/policies/sync') {
          res.writeHead(404).end();
          return;
        }
        if (req.headers['if-none-match'] === `"${policy.etag}"`) {
          res.writeHead(304).end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: `"${policy.etag}"` });
        res.end(JSON.stringify(policy.body));
      }
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    port = (server.address() as AddressInfo).port;
    fs.writeFileSync(
      path.join(home, '.node9', 'credentials.json'),
      JSON.stringify({
        default: { apiKey: 'test-key', apiUrl: `https://127.0.0.1:${port}/api/v1/intercept` },
      })
    );
  });

  afterAll(() => {
    server?.close();
  });

  it('prints the state, then the change of a sync, then the last change on a 304', async () => {
    // 1. A first sync: the state, and nothing to compare with.
    policy = { etag: 'e1', body: body('observe', {}) };
    const first = await sync();
    expect(first.code, first.stderr).toBe(0);
    expect(first.stdout).toContain('Level: audit');
    expect(first.stdout).not.toContain('Changed in this sync');
    expect(first.stdout).not.toContain('Last change');

    // 2. The dashboard moved the workspace to Standard and blocked a connector.
    policy = {
      etag: 'e2',
      body: body('standard', { 'url:gmailmcp.googleapis.com': 'blocked' }),
    };
    const second = await sync();
    expect(second.code, second.stderr).toBe(0);
    expect(second.stdout).toContain('Changed in this sync:');
    expect(second.stdout).toContain('Level: audit → standard');
    expect(second.stdout).toContain(
      'MCP server url:gmailmcp.googleapis.com: no decision → blocked'
    );
    expect(second.stdout).toContain('Level: standard');
    expect(second.stdout).toContain('1 add-on blocked');

    // 3. Nothing new on the server (the daemon, or the sync above, got there
    //    first): the answer is 304, and the last change is still shown.
    const third = await sync();
    expect(third.code, third.stderr).toBe(0);
    expect(third.stdout).toContain('304');
    expect(third.stdout).toContain('Last change,');
    expect(third.stdout).toContain('Level: audit → standard');
    expect(third.stdout).not.toContain('Changed in this sync');
  }, 120_000);
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});
