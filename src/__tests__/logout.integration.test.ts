import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { spawn } from 'child_process';
import * as http from 'http';
import type { AddressInfo } from 'net';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

// `node9 logout` (login-v2 §5, phase C.2): revoke in the cloud, remove
// locally, keep local enforcement. Real spawn path against a mock of
// POST /machines/self/disconnect.
describe('node9 logout (integration)', () => {
  let server: http.Server;
  let port: number;
  let mode: 'ok' | '401' = 'ok';
  let sawAuth: string | null = null;
  let tmpHome: string;

  beforeAll(
    () =>
      new Promise<void>((resolve) => {
        server = http.createServer((req, res) => {
          if (req.method === 'POST' && req.url === '/api/v1/intercept/machines/self/disconnect') {
            sawAuth = req.headers.authorization ?? null;
            if (mode === '401') {
              res.writeHead(401);
              res.end('{}');
              return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true, name: 'MyDell' }));
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
    sawAuth = null;
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-logout-'));
  });
  afterEach(() => fs.rmSync(tmpHome, { recursive: true, force: true }));

  const credPath = () => path.join(tmpHome, '.node9', 'credentials.json');
  function writeCreds(profiles: Record<string, unknown>) {
    fs.mkdirSync(path.dirname(credPath()), { recursive: true });
    fs.writeFileSync(credPath(), JSON.stringify(profiles));
  }
  const apiUrl = () => `http://127.0.0.1:${port}/api/v1/intercept`;

  function run(env: Record<string, string> = {}) {
    return new Promise<{ status: number | null; out: string }>((resolve) => {
      const child = spawn(process.execPath, [CLI, 'logout'], {
        env: {
          ...process.env,
          NODE9_TESTING: '1',
          NODE9_NO_AUTO_DAEMON: '1',
          HOME: tmpHome,
          USERPROFILE: tmpHome,
          ...env,
        },
      });
      let out = '';
      child.stdout.on('data', (d) => (out += d));
      child.stderr.on('data', (d) => (out += d));
      child.on('close', (status) => resolve({ status, out }));
    });
  }

  it('revokes in the cloud WITH the key, then removes it locally', async () => {
    mode = 'ok';
    writeCreds({ default: { apiKey: 'n9_live_bye', apiUrl: apiUrl() } });
    const r = await run();
    expect(r.status).toBe(0);
    expect(sawAuth).toBe('Bearer n9_live_bye');
    expect(r.out).toMatch(/key revoked \(MyDell\)/);
    expect(r.out).toMatch(/credentials removed/);
    // Local enforcement message — logout must never read as "unprotected".
    expect(r.out).toMatch(/Local enforcement keeps running/);
    expect(fs.existsSync(credPath())).toBe(false);
  });

  it('a key already revoked from the dashboard reads as "already disconnected"', async () => {
    mode = '401';
    writeCreds({ default: { apiKey: 'n9_live_bye', apiUrl: apiUrl() } });
    const r = await run();
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/already disconnected/);
    expect(fs.existsSync(credPath())).toBe(false);
  });

  it('an unreachable cloud still logs out locally — and says the dashboard row remains', async () => {
    writeCreds({
      default: { apiKey: 'n9_live_bye', apiUrl: 'http://127.0.0.1:9/api/v1/intercept' },
    });
    const r = await run();
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/Could not reach the cloud/);
    expect(r.out).toMatch(/still listed in the dashboard/);
    expect(fs.existsSync(credPath())).toBe(false);
  });

  it('removes ONLY the active profile; other profiles survive', async () => {
    mode = 'ok';
    writeCreds({
      default: { apiKey: 'n9_live_keepme', apiUrl: apiUrl() },
      dev: { apiKey: 'n9_live_bye', apiUrl: apiUrl() },
    });
    const r = await run({ NODE9_PROFILE: 'dev' });
    expect(r.status).toBe(0);
    expect(sawAuth).toBe('Bearer n9_live_bye');
    const left = JSON.parse(fs.readFileSync(credPath(), 'utf-8'));
    expect(left.default.apiKey).toBe('n9_live_keepme');
    expect(left.dev).toBeUndefined();
  });

  it('not logged in → says so, exits 0, touches nothing', async () => {
    const r = await run();
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/Not logged in/);
    expect(sawAuth).toBeNull();
  });
});
