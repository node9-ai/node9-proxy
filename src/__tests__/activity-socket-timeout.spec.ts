// The flight-recorder socket must never hold a hook call. Every hook awaits
// notifyActivitySocket before the gate judges and again after; a daemon that
// accepts the connection and never closes it (event loop blocked, a debugger,
// SIGSTOP) used to freeze every agent tool call. Real sockets, private paths.
import { describe, it, expect, afterEach } from 'vitest';
import net from 'net';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { randomUUID } from 'crypto';
import { notifyActivitySocket } from '../auth/daemon';

const servers: net.Server[] = [];
const accepted = new Set<net.Socket>();
const dirs: string[] = [];

function socketPath(): string {
  if (process.platform === 'win32') return `\\\\.\\pipe\\node9-test-${randomUUID()}`;
  // Short: a Unix socket path is limited to ~104 bytes.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n9s-'));
  dirs.push(dir);
  return path.join(dir, 's.sock');
}

function listen(server: net.Server, p: string): Promise<void> {
  servers.push(server);
  return new Promise((resolve) => server.listen(p, () => resolve()));
}

afterEach(async () => {
  // A half-open listener never ends its connections; close() waits for them.
  for (const c of accepted) c.destroy();
  accepted.clear();
  for (const s of servers.splice(0)) await new Promise<void>((r) => s.close(() => r()));
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe('notifyActivitySocket', () => {
  // POSIX only: on a Windows named pipe the client's half-close ends the
  // connection, so an in-process listener cannot play a daemon that never
  // closes; the timeout itself is platform-neutral.
  it.skipIf(process.platform === 'win32')(
    'a listener that accepts and never closes: false after the timeout, and the client socket is released',
    async () => {
      const p = socketPath();
      // allowHalfOpen: the server keeps its side open after the client's end,
      // as a daemon whose event loop never runs again would.
      const stuck = net.createServer({ allowHalfOpen: true }, (c) => accepted.add(c));
      await listen(stuck, p);
      const pipes = () => process.getActiveResourcesInfo().filter((r) => r === 'PipeWrap').length;
      const before = pipes();
      const t0 = Date.now();
      const ok = await notifyActivitySocket(
        { id: 'x', status: 'pending' },
        { timeoutMs: 200, socketPath: p }
      );
      const took = Date.now() - t0;
      expect(ok).toBe(false);
      expect(took).toBeGreaterThanOrEqual(190);
      expect(took).toBeLessThan(1200);
      // The server's accepted side stays open (half-open); the client side is
      // gone once libuv has run its close callback (a loop turn or two).
      const deadline = Date.now() + 500;
      while (pipes() > before + 1 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(pipes()).toBe(before + 1);
    }
  );

  it('a listener that reads to the end and closes: true, and the payload arrived', async () => {
    const p = socketPath();
    let received = '';
    const healthy = net.createServer((sock) => {
      sock.on('data', (d) => (received += String(d)));
    });
    await listen(healthy, p);
    const ok = await notifyActivitySocket(
      { id: 'y', status: 'pending' },
      { timeoutMs: 2000, socketPath: p }
    );
    expect(ok).toBe(true);
    expect(JSON.parse(received)).toEqual({ id: 'y', status: 'pending' });
  });

  it('no listener: false at once', async () => {
    const p = socketPath();
    const t0 = Date.now();
    const ok = await notifyActivitySocket({ id: 'z' }, { timeoutMs: 5000, socketPath: p });
    expect(ok).toBe(false);
    expect(Date.now() - t0).toBeLessThan(1000);
  });
});
