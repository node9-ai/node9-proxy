import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import * as http from 'http';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { AddressInfo } from 'net';
import { getMachineId } from '../machine-id';
import { runDeviceLogin } from '../auth/device-login';

// ── machine-id ────────────────────────────────────────────────────────────
describe('getMachineId', () => {
  let tmp: string;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-mid-'));
  });
  afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('mints once and stays stable across calls (the no-ghost-machines property)', () => {
    const a = getMachineId(tmp);
    const b = getMachineId(tmp);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f-]{36}$/);
    expect(fs.readFileSync(path.join(tmp, '.node9', 'machine-id'), 'utf-8').trim()).toBe(a);
  });

  it('re-mints over corrupt content instead of trusting garbage', () => {
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.writeFileSync(path.join(tmp, '.node9', 'machine-id'), 'not-a-uuid\n');
    const id = getMachineId(tmp);
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(getMachineId(tmp)).toBe(id);
  });
});

// ── device login flow against a mock server ───────────────────────────────
describe('runDeviceLogin', () => {
  let server: http.Server;
  let base: string;
  // Scripted poll outcomes, shifted per request.
  let pollScript: Array<Record<string, unknown>>;
  let startCount = 0;
  let lastStartBody: Record<string, unknown> | null = null;

  beforeAll(
    () =>
      new Promise<void>((resolve) => {
        server = http.createServer((req, res) => {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            const parsed = body ? (JSON.parse(body) as Record<string, unknown>) : {};
            if (req.url === '/device/start') {
              startCount++;
              lastStartBody = parsed;
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  userCode: 'ABCD-EFGH',
                  pollToken: 'n9_poll_test',
                  verificationUrl: 'https://node9.ai/device?code=ABCD-EFGH',
                  intervalSec: 0.01,
                  expiresInSec: 2,
                })
              );
            } else if (req.url === '/device/poll') {
              const next = pollScript.shift() ?? { status: 'pending' };
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(next));
            } else {
              res.writeHead(404);
              res.end();
            }
          });
        });
        server.listen(0, '127.0.0.1', () => {
          base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
          resolve();
        });
      })
  );
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  beforeEach(() => {
    pollScript = [];
    startCount = 0;
    lastStartBody = null;
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());

  const opts = () => ({ apiUrl: `${base}/device/start`, noBrowser: true, cliVersion: '9.9.9' });

  it('sends machine metadata, waits through pending, returns the key on approval', async () => {
    pollScript = [
      { status: 'pending' },
      { status: 'pending' },
      {
        status: 'approved',
        apiKey: 'n9_live_won',
        workspaceId: 'ws-1',
        workspaceName: 'Acme',
        machineName: 'Named-In-Browser',
      },
    ];
    const r = await runDeviceLogin(opts());
    expect(r).toEqual({
      ok: true,
      apiKey: 'n9_live_won',
      workspaceName: 'Acme',
      machineName: 'Named-In-Browser',
    });
    expect(startCount).toBe(1);
    expect(lastStartBody).toMatchObject({
      hostname: os.hostname(),
      platform: process.platform,
      cliVersion: '9.9.9',
    });
    expect(typeof lastStartBody?.machineId).toBe('string');
  });

  it('a browser denial ends the flow with a clear reason', async () => {
    pollScript = [{ status: 'denied' }];
    const r = await runDeviceLogin(opts());
    expect(r).toEqual({ ok: false, reason: expect.stringContaining('denied') });
  });

  it('an expired code tells the user to rerun login', async () => {
    pollScript = [{ status: 'expired' }];
    const r = await runDeviceLogin(opts());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('node9 login');
  });

  it('an unreachable server fails the start step, not a hang', async () => {
    const r = await runDeviceLogin({ apiUrl: 'http://127.0.0.1:9/device/start', noBrowser: true });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('Could not reach');
  });
});
