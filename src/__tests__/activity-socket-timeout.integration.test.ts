// A hook call answers even when something holds the flight-recorder socket
// and never closes it. Before the timeout, `node9 check` waited on it before
// judging, so the agent's tool call hung until the agent gave up.
import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'child_process';
import net from 'net';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
let root = '';
let server: net.Server | null = null;
const accepted = new Set<net.Socket>();

afterEach(async () => {
  // The stuck listener never ends its connections; close() waits for them.
  for (const c of accepted) c.destroy();
  accepted.clear();
  if (server) await new Promise<void>((r) => server!.close(() => r()));
  server = null;
  if (root) fs.rmSync(root, { recursive: true, force: true });
});

describe.skipIf(process.platform === 'win32')('node9 check with a stuck activity socket', () => {
  it('answers within seconds instead of waiting on the socket', async () => {
    // Short private paths: TMPDIR decides where the hook looks for the socket.
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'n9st-'));
    const home = path.join(root, 'h');
    const tmp = path.join(root, 't');
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.mkdirSync(tmp);
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { mode: 'standard' } })
    );
    // Accepts every connection and never closes one.
    server = net.createServer({ allowHalfOpen: true }, (c) => accepted.add(c));
    await new Promise<void>((r) =>
      server!.listen(path.join(tmp, 'node9-activity.sock'), () => r())
    );

    const env: Record<string, string | undefined> = { ...process.env };
    delete env.NODE9_API_KEY;
    delete env.NODE9_API_URL;
    const input = JSON.stringify({
      session_id: 's1',
      tool_name: 'Read',
      tool_input: { file_path: path.join(home, 'a.txt') },
      cwd: home,
    });
    const t0 = Date.now();
    const result = await new Promise<{ status: number | null; timedOut: boolean }>((resolve) => {
      const child = spawn(process.execPath, [CLI, 'check'], {
        cwd: home,
        env: {
          ...env,
          HOME: home,
          USERPROFILE: home,
          TMPDIR: tmp,
          NODE9_TESTING: '1',
          NODE9_NO_AUTO_DAEMON: '1',
          CLAUDECODE: '1',
        },
      });
      const limit = setTimeout(() => {
        child.kill('SIGKILL');
        resolve({ status: null, timedOut: true });
      }, 20_000);
      child.on('exit', (status) => {
        clearTimeout(limit);
        resolve({ status, timedOut: false });
      });
      child.stdin.end(input);
    });
    expect(result.timedOut, 'node9 check hung on the activity socket').toBe(false);
    expect(result.status).toBe(0);
    expect(Date.now() - t0).toBeLessThan(10_000);
  }, 30_000);
});
