import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { spawn } from 'child_process';
import * as http from 'http';
import type { AddressInfo } from 'net';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

// Spawns `dist/cli.js connect <token>` against a local mock of POST /cli/connect.
// Uses async spawn (NOT spawnSync) so the parent event loop stays free to serve
// the in-process mock. NODE9_TESTING=1 skips the post-connect cloud sync.
describe('node9 connect (integration)', () => {
  let server: http.Server;
  let port: number;
  let mode: 'ok' | '401' = 'ok';
  let tmpHome: string;

  beforeAll(
    () =>
      new Promise<void>((resolve) => {
        server = http.createServer((req, res) => {
          if (req.method === 'POST' && req.url === '/cli/connect') {
            if (mode === '401') {
              res.writeHead(401);
              res.end('expired');
              return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                apiKey: 'n9_live_test',
                workspaceId: 'ws-1',
                workspaceName: 'Acme',
              })
            );
          } else {
            res.writeHead(404);
            res.end();
          }
        });
        server.listen(0, '127.0.0.1', () => {
          port = (server.address() as AddressInfo).port;
          resolve();
        });
      })
  );

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-connect-'));
  });
  afterEach(() => fs.rmSync(tmpHome, { recursive: true, force: true }));

  function runConnect(
    token: string
  ): Promise<{ status: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(
        process.execPath,
        [CLI, 'connect', token, '--api-url', `http://127.0.0.1:${port}/cli/connect`],
        {
          env: {
            ...process.env,
            NODE9_TESTING: '1',
            NODE9_NO_AUTO_DAEMON: '1',
            HOME: tmpHome,
            USERPROFILE: tmpHome,
          },
        }
      );
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('close', (status) => resolve({ status, stdout, stderr }));
    });
  }

  const credsPath = () => path.join(tmpHome, '.node9', 'credentials.json');

  it('exchanges a token → writes creds + prints connected', async () => {
    mode = 'ok';
    const r = await runConnect('n9_connect_valid');
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Connected to Acme/);
    const creds = JSON.parse(fs.readFileSync(credsPath(), 'utf-8'));
    expect(creds.default.apiKey).toBe('n9_live_test');
  });

  it('rejects an expired/used token → exit 1, no creds written', async () => {
    mode = '401';
    const r = await runConnect('n9_connect_expired');
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/expired or was already used/);
    expect(fs.existsSync(credsPath())).toBe(false);
  });
});
