/**
 * The hook's wait on a daemon card must outlast 300 s (review of 232b7e8).
 *
 * The terminal racer long-polls GET /wait/<id>, and the daemon sends the
 * response headers only when the card is decided. The global fetch (undici)
 * ends a request with no headers after 300 s (headersTimeout), so every wait
 * longer than that failed: approvalTimeoutMs 0 ("no timer") and any timeout
 * of 295 s or more lost the card in node9 tail at 300 s.
 *
 * Slow (about 5.5 minutes), so it runs only with NODE9_SLOW_TESTS=1:
 *   NODE9_SLOW_TESTS=1 npx vitest --run src/__tests__/daemon-wait-long.integration.test.ts
 *
 * A real daemon from dist/cli.js in an isolated HOME on its own port
 * (NODE9_DAEMON_PORT, honoured under NODE9_TESTING=1), and the hook's real
 * waitForDaemonDecision.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const SLOW = process.env.NODE9_SLOW_TESTS === '1';
/** Past undici's 300 s headersTimeout. */
const DECIDE_AFTER_MS = 310_000;

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      server.close(() => resolve(port));
    });
  });
}

async function waitForDaemon(port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/settings`);
      if (res.status < 500) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

describe.skipIf(!SLOW)('a wait on a daemon card outlasts 300 s', () => {
  let home = '';
  let port = 0;
  let proc: ChildProcess | undefined;
  let env: NodeJS.ProcessEnv = {};
  const savedPort = process.env.NODE9_DAEMON_PORT;

  beforeAll(async () => {
    if (!fs.existsSync(CLI)) {
      throw new Error(`dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`);
    }
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-wait-long-'));
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    // Audit mode: the background pass leaves the card for a person; 0: no timer.
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { mode: 'audit', autoStartDaemon: false, approvalTimeoutMs: 0 } })
    );
    port = await freePort();
    env = {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_DAEMON_PORT: String(port),
    };
    proc = spawn(process.execPath, [CLI, 'daemon', 'start'], { env, stdio: 'pipe' });
    if (!(await waitForDaemon(port, 8000))) throw new Error('Daemon did not start within 8s');
  }, 15_000);

  afterAll(() => {
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], { env, timeout: 3000 });
    if (proc && proc.exitCode === null) proc.kill();
    if (home) fs.rmSync(home, { recursive: true, force: true });
    if (savedPort === undefined) delete process.env.NODE9_DAEMON_PORT;
    else process.env.NODE9_DAEMON_PORT = savedPort;
  });

  it(
    "a person's deny after 310 s reaches the hook",
    async () => {
      const base = `http://127.0.0.1:${port}`;
      const reg = await fetch(`${base}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toolName: 'bash', args: { command: 'echo wait-long' } }),
      });
      expect(reg.ok).toBe(true);
      const { id } = (await reg.json()) as { id: string };

      // The hook's own client, pointed at this daemon. Cap 0: no cap, as the
      // hook passes for approvalTimeoutMs 0.
      vi.resetModules();
      process.env.NODE9_DAEMON_PORT = String(port);
      const { waitForDaemonDecision } = await import('../auth/daemon.js');
      const waiting = waitForDaemonDecision(id, undefined, 0);
      const outcome = waiting.then(
        (r) => ({ ok: true as const, r }),
        (err: Error) => ({ ok: false as const, err })
      );

      await new Promise((r) => setTimeout(r, DECIDE_AFTER_MS));
      const pid = JSON.parse(fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf-8')) as {
        internalToken?: string;
      };
      const decided = await fetch(`${base}/decision/${id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Node9-Internal': pid.internalToken ?? '',
        },
        body: JSON.stringify({ decision: 'deny', source: 'terminal' }),
      });
      // 404 here means the card was already gone: the wait was cut and the
      // daemon removed the card when the long-poll closed.
      expect(decided.status).toBe(200);

      const res = await outcome;
      if (!res.ok) throw res.err;
      expect(res.r).toEqual({ decision: 'deny', source: 'terminal', reason: undefined });
    },
    DECIDE_AFTER_MS + 60_000
  );
});
