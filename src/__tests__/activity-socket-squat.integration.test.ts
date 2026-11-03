// A socket another user created in a shared directory must receive nothing
// from the hook (activity-socket-ownership design, 2026-11-02). Before the
// fix, the hook connected to $TMPDIR/node9-activity.sock (the shared /tmp on
// Linux) whoever had bound it, and sent every tool call with its arguments.
import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
let root = '';
let server: net.Server | null = null;

afterEach(async () => {
  if (server) await new Promise<void>((r) => server!.close(() => r()));
  server = null;
  if (root) fs.rmSync(root, { recursive: true, force: true });
});

/** A listener that records whatever a client sends it. */
async function squatter(socketPath: string): Promise<string[]> {
  const got: string[] = [];
  server = net.createServer((c) => {
    let buf = '';
    c.on('data', (d) => (buf += d.toString()));
    c.on('end', () => {
      got.push(buf);
      c.end();
    });
  });
  await new Promise<void>((r) => server!.listen(socketPath, () => r()));
  return got;
}

function check(home: string, tmp: string): number | null {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  delete env.XDG_RUNTIME_DIR;
  const r = spawnSync(process.execPath, [CLI, 'check'], {
    cwd: home,
    input: JSON.stringify({
      session_id: 'squat',
      tool_name: 'Bash',
      tool_input: { command: 'echo SECRET-ARGUMENT' },
      cwd: home,
    }),
    env: {
      ...env,
      HOME: home,
      USERPROFILE: home,
      TMPDIR: tmp,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      CLAUDECODE: '1',
    },
    encoding: 'utf8',
    timeout: 30_000,
  });
  expect(r.error).toBeUndefined();
  return r.status;
}

describe.skipIf(process.platform === 'win32')('a squatted activity socket', () => {
  it('the old shared path gets nothing from a hook call', async () => {
    expect(fs.existsSync(CLI), 'dist/cli.js missing: run npm run build').toBe(true);
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'n9q-'));
    const home = path.join(root, 'h');
    const tmp = path.join(root, 't');
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.mkdirSync(tmp);
    const got = await squatter(path.join(tmp, 'node9-activity.sock'));
    expect(check(home, tmp)).toBe(0);
    await new Promise((r) => setTimeout(r, 200));
    expect(got).toEqual([]);
  });

  it('a socket named in daemon.pid but in a directory others can write gets nothing', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'n9q-'));
    const home = path.join(root, 'h');
    const tmp = path.join(root, 't');
    const shared = path.join(root, 's');
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.mkdirSync(tmp);
    fs.mkdirSync(shared);
    fs.chmodSync(shared, 0o777);
    const socketPath = path.join(shared, 'activity.sock');
    const got = await squatter(socketPath);
    fs.writeFileSync(
      path.join(home, '.node9', 'daemon.pid'),
      JSON.stringify({
        pid: 2 ** 22 + 7,
        port: 1,
        internalToken: null,
        activitySocket: socketPath,
      }),
      { mode: 0o600 }
    );
    expect(check(home, tmp)).toBe(0);
    await new Promise((r) => setTimeout(r, 200));
    expect(got).toEqual([]);
  });

  it('a socket of this user in a private directory, named in daemon.pid, gets the line', async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'n9q-'));
    const home = path.join(root, 'h');
    const tmp = path.join(root, 't');
    const run = path.join(home, '.node9', 'run');
    fs.mkdirSync(run, { recursive: true, mode: 0o700 });
    fs.mkdirSync(tmp);
    const socketPath = path.join(run, 'activity.sock');
    const got = await squatter(socketPath);
    fs.writeFileSync(
      path.join(home, '.node9', 'daemon.pid'),
      JSON.stringify({
        pid: 2 ** 22 + 7,
        port: 1,
        internalToken: null,
        activitySocket: socketPath,
      }),
      { mode: 0o600 }
    );
    expect(check(home, tmp)).toBe(0);
    await new Promise((r) => setTimeout(r, 200));
    expect(got.length).toBeGreaterThan(0);
    expect(got.join('')).toContain('squat');
  });
});
