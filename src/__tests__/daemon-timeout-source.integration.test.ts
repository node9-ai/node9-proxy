/**
 * Who resolved a daemon card, as GET /wait reports it (ENG-2, node9Firewall#304).
 *
 * - The auto-deny timer answers with `source: 'timeout'`, so the hook can
 *   tell "nobody answered" from a person refusing. Before the fix the timer's
 *   deny carried no source, and the terminal racer reported it to the agent as
 *   "The human user rejected this action via the Node9 Terminal".
 * - A card the daemon's own background pass resolved names the pass's
 *   decider ('policy' for a rule; 'cloud' for its cloud racer), so the hook
 *   does not credit a rule with an administrator's deny, or the reverse.
 * - approvalTimeoutMs: 0 is "no timer": the card stays open, a person's
 *   decision is delivered, and the tail is told there is no countdown.
 *
 * Runs a real daemon from dist/cli.js in an isolated HOME on its own port
 * (NODE9_DAEMON_PORT, honoured under NODE9_TESTING=1), so a developer's live
 * daemon on 7391 is never touched.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import http from 'http';
import net from 'net';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const TIMEOUT_MS = 2000;

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

interface Daemon {
  home: string;
  port: number;
  /** POST /check: a card for `command`; the daemon's background pass runs on it. */
  register(command: string): Promise<string>;
  wait(id: string, signal?: AbortSignal): Promise<Response>;
  internalToken(): string;
  stop(): void;
}

/** A real daemon with this config in its own HOME and port. */
async function startDaemon(config: Record<string, unknown>): Promise<Daemon> {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`);
  }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-wait-source-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(path.join(home, '.node9', 'config.json'), JSON.stringify(config));
  const port = await freePort();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_DAEMON_PORT: String(port),
  };
  const proc: ChildProcess = spawn(process.execPath, [CLI, 'daemon', 'start'], {
    env,
    stdio: 'pipe',
  });
  if (!(await waitForDaemon(port, 8000))) {
    proc.kill();
    throw new Error('Daemon did not start within 8s');
  }
  const base = `http://127.0.0.1:${port}`;
  return {
    home,
    port,
    async register(command) {
      const res = await fetch(`${base}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toolName: 'bash', args: { command } }),
      });
      expect(res.ok).toBe(true);
      return ((await res.json()) as { id: string }).id;
    },
    wait: (id, signal) => fetch(`${base}/wait/${id}`, { signal }),
    internalToken() {
      const pid = JSON.parse(fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf-8')) as {
        internalToken?: string;
      };
      return pid.internalToken ?? '';
    },
    stop() {
      spawnSync(process.execPath, [CLI, 'daemon', 'stop'], { env, timeout: 3000 });
      if (proc.exitCode === null) proc.kill();
      fs.rmSync(home, { recursive: true, force: true });
    },
  };
}

/** The `init` event the daemon sends a new SSE subscriber (node9 tail). */
function readInitEvent(port: number, token: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let data = '';
    const req = http.get(
      `http://127.0.0.1:${port}/events`,
      { headers: { 'X-Node9-Internal': token } },
      (res) => {
        res.setEncoding('utf-8');
        res.on('data', (chunk: string) => {
          data += chunk;
          const m = /event: init\ndata: (.*)\n/.exec(data);
          if (m) {
            req.destroy();
            resolve(JSON.parse(m[1]) as Record<string, unknown>);
          }
        });
      }
    );
    req.on('error', (err) => {
      if (!data.includes('event: init')) reject(err);
    });
    setTimeout(() => {
      req.destroy();
      reject(new Error(`no init event: ${data.slice(0, 200)}`));
    }, 5000);
  });
}

describe('daemon auto-deny timer reports source=timeout (ENG-2)', () => {
  let d: Daemon;
  beforeAll(async () => {
    // Audit mode: the background pass leaves the card for a person, so only
    // the timer can end it.
    d = await startDaemon({
      settings: { mode: 'audit', autoStartDaemon: false, approvalTimeoutMs: TIMEOUT_MS },
    });
  }, 15_000);
  afterAll(() => d?.stop());

  it('a /wait that is open when the timer fires gets source=timeout', async () => {
    const id = await d.register('echo timeout-source');
    const waitRes = await d.wait(id);
    expect(waitRes.ok).toBe(true);
    const body = (await waitRes.json()) as { decision: string; source?: string };
    expect(body.decision).toBe('deny');
    expect(body.source).toBe('timeout');
  });
});

// fw#304 review, finding 1: the background pass resolved the card with no
// source, so the hook could not tell its rule from its cloud racer.
describe("a card the daemon's background pass blocked reports source=policy", () => {
  let d: Daemon;
  beforeAll(async () => {
    d = await startDaemon({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 60_000,
        approvers: { native: false, browser: false, cloud: false, terminal: true },
      },
      policy: {
        smartRules: [
          {
            name: 'block-pass-probe',
            tool: 'bash',
            conditions: [{ field: 'command', op: 'matches', value: '^echo pass-probe' }],
            conditionMode: 'all',
            verdict: 'block',
            reason: 'blocked by the pass probe rule',
          },
        ],
      },
    });
  }, 15_000);
  afterAll(() => d?.stop());

  it('the pass blocks by rule: deny with source=policy and the rule reason', async () => {
    const id = await d.register('echo pass-probe');
    const waitRes = await d.wait(id);
    expect(waitRes.ok).toBe(true);
    const body = (await waitRes.json()) as { decision: string; source?: string; reason?: string };
    expect(body.decision).toBe('deny');
    expect(body.source).toBe('policy');
    expect(body.reason).toBe('blocked by the pass probe rule');
  });
});

// approvalTimeoutMs: 0 means "no timer". The daemon read it with `??` and
// armed a 0 ms timer: every card was denied the moment it opened, before any
// person could see it. Now no timer is armed at all.
describe('daemon with approvalTimeoutMs 0 has no timer', () => {
  let d: Daemon;
  beforeAll(async () => {
    d = await startDaemon({
      settings: { mode: 'audit', autoStartDaemon: false, approvalTimeoutMs: 0 },
    });
  }, 15_000);
  afterAll(() => d?.stop());

  it('the card waits for a person, and their decision is delivered', async () => {
    const id = await d.register('echo timeout-zero');
    const waiting = d.wait(id);
    // Before the fix the card was denied and gone within milliseconds.
    await new Promise((r) => setTimeout(r, 1500));
    const decided = await fetch(`http://127.0.0.1:${d.port}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': d.internalToken() },
      body: JSON.stringify({ decision: 'deny', source: 'terminal' }),
    });
    expect(decided.status).toBe(200);

    const waitRes = await waiting;
    expect(waitRes.ok).toBe(true);
    const body = (await waitRes.json()) as { decision: string; source?: string };
    expect(body.decision).toBe('deny');
    expect(body.source).toBe('terminal');
  });

  it('the tail is told there is no countdown', async () => {
    const init = await readInitEvent(d.port, d.internalToken());
    expect(init.autoDenyMs).toBeNull();
  });
});
