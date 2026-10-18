// The /wait long-poll's own cap must surface as a failed channel. The race
// ignores an AbortError (it means the race itself ended), so a cap that
// rejected with one silently dropped the terminal racer, and a race with no
// other racer never resolved (fw#304 review round 2).
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import http from 'http';
import type { AddressInfo } from 'net';

let server: http.Server;
let port = 0;

beforeAll(async () => {
  // A daemon that accepts /wait and never answers.
  server = http.createServer(() => {});
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => {
  server.closeAllConnections();
  server.close();
});

async function loadWait() {
  vi.resetModules();
  process.env.NODE9_DAEMON_PORT = String(port);
  return (await import('../auth/daemon.js')).waitForDaemonDecision;
}

describe('waitForDaemonDecision cap', () => {
  it('rejects with a non-abort error when its own cap fires', async () => {
    const wait = await loadWait();
    const err = await wait('id-1', undefined, 200).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).name).not.toBe('AbortError');
    expect((err as Error).message).toMatch(/did not answer in time/);
  });

  it('the race aborting it still rejects as an abort', async () => {
    const wait = await loadWait();
    const ctrl = new AbortController();
    const p = wait('id-2', ctrl.signal, 5000).catch((e: Error) => e);
    setTimeout(() => ctrl.abort(), 50);
    const err = (await p) as Error;
    expect(err.name).toBe('AbortError');
  });
});
