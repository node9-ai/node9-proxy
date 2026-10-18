/**
 * ENG-2 (node9Firewall#304): the daemon's auto-deny timer answers /wait with
 * `source: 'timeout'`, so the hook can tell "nobody answered" from a person
 * refusing. Before the fix the timer's deny carried no source, and the
 * terminal racer reported it to the agent as "The human user rejected this
 * action via the Node9 Terminal".
 *
 * Runs a real daemon from dist/cli.js in an isolated HOME on its own port
 * (NODE9_DAEMON_PORT, honoured under NODE9_TESTING=1), so a developer's live
 * daemon on 7391 is never touched.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
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

describe('daemon auto-deny timer reports source=timeout (ENG-2)', () => {
  let tmpHome = '';
  let port = 0;
  let env: NodeJS.ProcessEnv = {};
  let daemonProc: ChildProcess | undefined;

  beforeAll(async () => {
    if (!fs.existsSync(CLI)) {
      throw new Error(`dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`);
    }
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-timeout-src-'));
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    // Audit mode: the daemon's background pass leaves the card for a person,
    // so only the timer can end it.
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: { mode: 'audit', autoStartDaemon: false, approvalTimeoutMs: TIMEOUT_MS },
      })
    );
    port = await freePort();
    env = {
      ...process.env,
      HOME: tmpHome,
      USERPROFILE: tmpHome,
      NODE9_TESTING: '1',
      NODE9_DAEMON_PORT: String(port),
    };
    daemonProc = spawn(process.execPath, [CLI, 'daemon', 'start'], { env, stdio: 'pipe' });
    if (!(await waitForDaemon(port, 8000))) {
      daemonProc.kill();
      throw new Error('Daemon did not start within 8s');
    }
  }, 15_000);

  afterAll(() => {
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], { env, timeout: 3000 });
    if (daemonProc?.exitCode === null) daemonProc.kill();
    if (tmpHome) fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  async function registerEntry(): Promise<string> {
    const res = await fetch(`http://127.0.0.1:${port}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ toolName: 'bash', args: { command: 'echo timeout-source' } }),
    });
    expect(res.ok).toBe(true);
    const { id } = (await res.json()) as { id: string };
    return id;
  }

  it('a /wait that is open when the timer fires gets source=timeout', async () => {
    const id = await registerEntry();
    const waitRes = await fetch(`http://127.0.0.1:${port}/wait/${id}`);
    expect(waitRes.ok).toBe(true);
    const body = (await waitRes.json()) as { decision: string; source?: string };
    expect(body.decision).toBe('deny');
    expect(body.source).toBe('timeout');
  });
});
