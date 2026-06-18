// src/__tests__/session-taint-integration.spec.ts
// Route-contract tests for the gap1 session-taint daemon endpoints
// (/session-taint, /session-taint/check). Mirrors taint-integration.spec.ts:
// spins a minimal stub daemon backed by the REAL SessionTaintStore so the
// request/response shape the client (notifySessionTaint/checkSessionTaint)
// depends on is locked.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import { SessionTaintStore } from '../daemon/taint-store.js';

const store = new SessionTaintStore();

async function readBody(req: http.IncomingMessage): Promise<string> {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  return raw;
}

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer(async (req, res) => {
    const pathname = new URL(req.url || '/', `http://127.0.0.1`).pathname;
    if (req.method === 'POST' && pathname === '/session-taint') {
      try {
        const body = JSON.parse(await readBody(req)) as {
          sessionId?: unknown;
          source?: unknown;
        };
        if (typeof body.sessionId !== 'string' || typeof body.source !== 'string') {
          res.writeHead(400).end(JSON.stringify({ error: 'bad' }));
          return;
        }
        store.taint(body.sessionId, body.source);
        res.writeHead(200).end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
      return;
    }
    if (req.method === 'POST' && pathname === '/session-taint/check') {
      try {
        const body = JSON.parse(await readBody(req)) as { sessionId?: unknown };
        if (typeof body.sessionId !== 'string') {
          res.writeHead(400).end(JSON.stringify({ error: 'bad' }));
          return;
        }
        const record = store.check(body.sessionId);
        res
          .writeHead(200)
          .end(JSON.stringify(record ? { tainted: true, record } : { tainted: false }));
      } catch {
        res.writeHead(400).end();
      }
      return;
    }
    if (req.method === 'GET' && pathname === '/session-taint/list') {
      res.writeHead(200).end(JSON.stringify({ records: store.list() }));
      return;
    }
    if (req.method === 'POST' && pathname === '/session-taint/clear') {
      try {
        const body = JSON.parse(await readBody(req)) as { sessionId?: unknown; all?: unknown };
        if (body.all === true) {
          const cleared = store.list().length;
          store.clear();
          res.writeHead(200).end(JSON.stringify({ ok: true, cleared }));
          return;
        }
        if (typeof body.sessionId !== 'string' || body.sessionId.length === 0) {
          res.writeHead(400).end(JSON.stringify({ error: 'bad' }));
          return;
        }
        const cleared = store.clearSession(body.sessionId) ? 1 : 0;
        res.writeHead(200).end(JSON.stringify({ ok: true, cleared }));
      } catch {
        res.writeHead(400).end();
      }
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as { port: number }).port;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

const base = () => `http://127.0.0.1:${port}`;

describe('session-taint daemon endpoints', () => {
  it('POST /session-taint then /check → tainted with the source', async () => {
    await fetch(`${base()}/session-taint`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 's1', source: 'output-secret:GitHubToken' }),
    });
    const res = await fetch(`${base()}/session-taint/check`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 's1' }),
    });
    const json = (await res.json()) as { tainted: boolean; record?: { source: string } };
    expect(json.tainted).toBe(true);
    expect(json.record?.source).toBe('output-secret:GitHubToken');
  });

  it('POST /session-taint/check → untainted session returns false', async () => {
    const res = await fetch(`${base()}/session-taint/check`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'never-tainted' }),
    });
    expect(((await res.json()) as { tainted: boolean }).tainted).toBe(false);
  });

  it('POST /session-taint → invalid body returns 400', async () => {
    const res = await fetch(`${base()}/session-taint`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 's1' }), // missing source
    });
    expect(res.status).toBe(400);
  });

  it('POST /session-taint/check → invalid body returns 400', async () => {
    const res = await fetch(`${base()}/session-taint/check`, {
      method: 'POST',
      body: JSON.stringify({}), // missing sessionId
    });
    expect(res.status).toBe(400);
  });

  it('GET /session-taint/list → returns the tainted records', async () => {
    await fetch(`${base()}/session-taint`, {
      method: 'POST',
      body: JSON.stringify({
        sessionId: 'list-me',
        source: 'output-injection:override-instructions',
      }),
    });
    const res = await fetch(`${base()}/session-taint/list`);
    const json = (await res.json()) as { records: Array<{ sessionId: string }> };
    expect(json.records.some((r) => r.sessionId === 'list-me')).toBe(true);
  });

  it('POST /session-taint/clear {sessionId} → clears it (cleared:1), check is false after', async () => {
    await fetch(`${base()}/session-taint`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'clear-me', source: 'output-secret:X' }),
    });
    const clr = await fetch(`${base()}/session-taint/clear`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'clear-me' }),
    });
    expect(((await clr.json()) as { cleared: number }).cleared).toBe(1);
    const chk = await fetch(`${base()}/session-taint/check`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'clear-me' }),
    });
    expect(((await chk.json()) as { tainted: boolean }).tainted).toBe(false);
  });

  it('POST /session-taint/clear {sessionId} for an untainted id → cleared:0', async () => {
    const clr = await fetch(`${base()}/session-taint/clear`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'was-never-here' }),
    });
    expect(((await clr.json()) as { cleared: number }).cleared).toBe(0);
  });

  it('POST /session-taint/clear {all:true} → clears every record', async () => {
    await fetch(`${base()}/session-taint`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'x1', source: 's' }),
    });
    await fetch(`${base()}/session-taint`, {
      method: 'POST',
      body: JSON.stringify({ sessionId: 'x2', source: 's' }),
    });
    const clr = await fetch(`${base()}/session-taint/clear`, {
      method: 'POST',
      body: JSON.stringify({ all: true }),
    });
    expect(((await clr.json()) as { cleared: number }).cleared).toBeGreaterThanOrEqual(2);
    const list = await fetch(`${base()}/session-taint/list`);
    expect(((await list.json()) as { records: unknown[] }).records).toHaveLength(0);
  });

  it('POST /session-taint/clear with neither sessionId nor all → 400', async () => {
    const res = await fetch(`${base()}/session-taint/clear`, {
      method: 'POST',
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });
});
