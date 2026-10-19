// The /wait long-poll's own cap must surface as a failed channel. The race
// ignores an AbortError (it means the race itself ended), so a cap that
// rejected with one silently dropped the terminal racer, and a race with no
// other racer never resolved (fw#304 review round 2).
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import http from 'http';
import type { AddressInfo } from 'net';
import fs from 'fs';
import os from 'os';
import path from 'path';

let server: http.Server;
let port = 0;

beforeAll(async () => {
  // A daemon that accepts /wait and, by default, never answers.
  server = http.createServer((req, res) => {
    if (req.url === '/wait/now') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ decision: 'deny', source: 'terminal', reason: 'no' }));
    } else if (req.url === '/wait/headers-then-hold') {
      // Headers now, the body never ends.
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.write('{"decision":');
    } else if (req.url === '/wait/headers-then-close') {
      // The daemon dies in the middle of its answer.
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.write('{"decision":');
      setTimeout(() => res.destroy(), 50);
    } else if (req.url === '/wait/headers-then-body') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.write('{"decision":');
      setTimeout(() => res.end('"allow","source":"terminal"}'), 100);
    }
  });
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

  // undici's fetch ends a request with no response headers after 300 s, and
  // the daemon answers /wait only when the card is decided, so a fetch-based
  // wait could never outlast 300 s (review of 232b7e8). The 300 s itself is
  // covered by daemon-wait-long.integration.test.ts (NODE9_SLOW_TESTS=1).
  it('does not go through fetch', async () => {
    const wait = await loadWait();
    vi.stubGlobal('fetch', () => Promise.reject(new Error('fetch must not be used for /wait')));
    try {
      await expect(wait('now', undefined, 5000)).resolves.toEqual({
        decision: 'deny',
        source: 'terminal',
        reason: 'no',
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('reads a body that arrives after the headers', async () => {
    const wait = await loadWait();
    await expect(wait('headers-then-body', undefined, 5000)).resolves.toEqual({
      decision: 'allow',
      source: 'terminal',
    });
  });

  it('its cap firing while the body is read is still a failed channel', async () => {
    const wait = await loadWait();
    const err = await wait('headers-then-hold', undefined, 200).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).name).not.toBe('AbortError');
    expect((err as Error).message).toMatch(/did not answer in time/);
  });

  it('a daemon that dies mid-answer fails the channel, with no cap', async () => {
    const wait = await loadWait();
    const err = await wait('headers-then-close', undefined, 0).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).name).not.toBe('AbortError');
  });
});

// Approval-card review: protocol 2 makes a card's /wait need the internal
// token, so the hook claims it only when it can read the token. A daemon
// under another uid is "running" (its pid probe fails with EPERM) but its
// token is unreadable: every wait would have got 403.
describe('registerDaemonEntry claims protocol 2 only with the token', () => {
  async function registerBody(home: string): Promise<Record<string, unknown>> {
    let seen: Record<string, unknown> = {};
    const srv = http.createServer((req, res) => {
      let b = '';
      req.on('data', (c) => (b += c));
      req.on('end', () => {
        seen = JSON.parse(b) as Record<string, unknown>;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'c1', allowCount: 1 }));
      });
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    const savedHome = process.env.HOME;
    try {
      vi.resetModules();
      process.env.NODE9_DAEMON_PORT = String((srv.address() as AddressInfo).port);
      process.env.HOME = home;
      const { registerDaemonEntry } = await import('../auth/daemon.js');
      await registerDaemonEntry('bash', { command: 'x' });
    } finally {
      process.env.HOME = savedHome;
      srv.close();
    }
    return seen;
  }

  it('with a readable token: protocol 2', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-reg-'));
    fs.mkdirSync(path.join(home, '.node9'));
    fs.writeFileSync(
      path.join(home, '.node9', 'daemon.pid'),
      JSON.stringify({ pid: process.pid, internalToken: 'tok' })
    );
    expect((await registerBody(home)).protocol).toBe(2);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('without one: no protocol, the card stays readable', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-reg-'));
    expect((await registerBody(home)).protocol).toBeUndefined();
    fs.rmSync(home, { recursive: true, force: true });
  });
});
