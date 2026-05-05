/**
 * Integration tests for the daemon SSE /events endpoint.
 *
 * Regression for: "Active Shields panel stuck on Loading — shields-status event
 * never emitted on connect". The fix emits shields-status in the initial SSE
 * payload alongside init and decisions.
 *
 * Requirements:
 *   - `npm run build` must be run before these tests (suite checks for dist/cli.js)
 *   - Port 7391 must be free — tests are skipped when another daemon is running
 *   - Tests use an isolated HOME to control shields state
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import http from 'http';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const DAEMON_PORT = 7391;

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(
      `dist/cli.js not found. Run "npm run build" before running integration tests.\nExpected: ${CLI}`
    );
  }
});

function makeTempHome(): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-daemon-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(
    path.join(node9Dir, 'config.json'),
    JSON.stringify({ settings: { mode: 'audit', autoStartDaemon: false } })
  );
  return tmpHome;
}

/** Returns a process env with both HOME and USERPROFILE pointing to the
 *  isolated home dir. Windows uses USERPROFILE; Unix uses HOME. */
function makeEnv(home: string): NodeJS.ProcessEnv {
  return { ...process.env, HOME: home, USERPROFILE: home, NODE9_TESTING: '1' };
}

function cleanupDir(dir: string) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e: unknown) {
    const code = (e as NodeJS.ErrnoException).code;
    // EBUSY: file locked by another process (common on Windows).
    // ENOTEMPTY: Windows creates system junctions (AppData\Local\Microsoft\Windows)
    //   inside any directory that becomes USERPROFILE — these can't be deleted
    //   by a plain rmdir but are harmless to leak from a CI temp dir.
    if (code === 'EBUSY' || code === 'ENOTEMPTY') {
      console.warn(`[cleanupDir] ${code} — temp dir leaked: ${dir}`);
      return;
    }
    throw e;
  }
}

function isPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => {
      server.close(() => resolve(true));
    });
    server.listen(port, '127.0.0.1');
  });
}

async function waitForDaemon(timeoutMs = 5000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/settings`);
      if (res.ok) return true;
    } catch (err) {
      lastErr = err; // capture for diagnostics — ECONNREFUSED is expected until ready
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  // Log the last error so CI failure messages explain why the daemon never responded
  // (e.g. EACCES on port, crashed on startup) rather than just "did not start within Xs"
  if (lastErr) process.stderr.write(`waitForDaemon: last error: ${lastErr}\n`);
  return false;
}

/**
 * Read the SSE /events stream for up to timeoutMs, then close.
 * Returns the raw text received.
 *
 * The /events endpoint requires a per-process auth token (v3 sprint #9).
 * Pass the token explicitly so tests can also exercise the unauth path
 * by passing an empty string / wrong value.
 */
function readSseStream(timeoutMs: number, authToken: string): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    let settled = false;
    const done = (value: string) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    const req = http.get(
      `http://127.0.0.1:${DAEMON_PORT}/events`,
      {
        headers: authToken ? { 'X-Node9-Internal': authToken } : {},
      },
      (res) => {
        res.setEncoding('utf-8');
        res.on('data', (chunk: string) => {
          data += chunk;
        });
        res.on('end', () => done(data));
        // After req.destroy() the res stream may still emit 'error' — guard with
        // settled flag so it doesn't fire reject after the Promise already resolved.
        res.on('error', () => {
          if (!settled) reject(new Error('SSE stream error'));
        });
      }
    );
    req.on('error', (err) => {
      if (!settled) reject(err);
    });
    // Close after timeoutMs — enough time to receive the initial burst of events.
    // Note: parseSseEvents silently drops multi-data-line events (valid SSE spec),
    // which is acceptable since all daemon events use a single data line.
    setTimeout(() => {
      req.destroy();
      done(data);
    }, timeoutMs);
  });
}

/**
 * Probe /events without sending an auth token. Returns the response
 * status code so tests can assert 403 on unauthenticated SSE access.
 */
function getEventsStatus(authHeader?: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      `http://127.0.0.1:${DAEMON_PORT}/events`,
      { headers: authHeader ? { 'X-Node9-Internal': authHeader } : {} },
      (res) => {
        const status = res.statusCode ?? 0;
        res.resume();
        req.destroy();
        resolve(status);
      }
    );
    req.on('error', reject);
  });
}

/**
 * Read the per-process auth token from the daemon's PID file. The CLI
 * `getInternalToken()` does the same thing — but tests can't import
 * from src/auth/daemon.ts directly without mocking os.homedir, so this
 * is a small focused reader used only by the integration suite.
 */
function readDaemonAuthToken(home: string): string {
  const pidFile = path.join(home, '.node9', 'daemon.pid');
  try {
    const data = JSON.parse(fs.readFileSync(pidFile, 'utf-8')) as Record<string, unknown>;
    return typeof data.internalToken === 'string' ? data.internalToken : '';
  } catch {
    return '';
  }
}

/**
 * Parse SSE stream text into a map of event name → parsed JSON payload.
 * When the same event appears multiple times, the last occurrence wins.
 */
function parseSseEvents(raw: string): Map<string, unknown> {
  const events = new Map<string, unknown>();
  for (const chunk of raw.split('\n\n')) {
    let eventName = 'message';
    let dataLine = '';
    for (const line of chunk.split('\n')) {
      if (line.startsWith('event: ')) eventName = line.slice(7).trim();
      if (line.startsWith('data: ')) dataLine = line.slice(6).trim();
    }
    if (dataLine) {
      try {
        events.set(eventName, JSON.parse(dataLine));
      } catch {
        // non-JSON data line — skip
      }
    }
  }
  return events;
}

// ── /events SSE — auth gate + initial events ──────────────────────────────────
// v3 sprint #9: /events now requires the per-process auth token. Closes the
// pre-v3 hole where any local process could subscribe and harvest the CSRF
// token + pending tool-call args. The 'shields-status', 'decisions', and 'csrf'
// initial-connect emissions were retired in the v3 browser-removal sprint —
// only `node9 tail` consumes /events now, and it doesn't need any of those.

describe('daemon /events — auth gate + initial event payload', () => {
  let tmpHome: string;
  let daemonProc: ChildProcess;
  // Captured once in beforeAll and shared across the tests below.
  let sseSnapshot: Map<string, unknown>;
  let authToken: string;
  let portWasFree = false;

  beforeAll(async () => {
    portWasFree = await isPortFree(DAEMON_PORT);
    if (!portWasFree) return;

    tmpHome = makeTempHome();
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'shields.json'),
      JSON.stringify({ active: ['filesystem'] })
    );

    try {
      daemonProc = spawn(process.execPath, [CLI, 'daemon', 'start'], {
        env: makeEnv(tmpHome),
        stdio: 'pipe',
      });

      const ready = await waitForDaemon(6000);
      if (!ready) {
        daemonProc.kill();
        throw new Error('Daemon did not start within 6s');
      }

      authToken = readDaemonAuthToken(tmpHome);

      // Capture the initial SSE burst once — shared by the tests below.
      const raw = await readSseStream(3000, authToken);
      sseSnapshot = parseSseEvents(raw);
    } catch (err) {
      if (tmpHome) cleanupDir(tmpHome);
      throw err;
    }
  }, 15_000);

  afterAll(() => {
    if (!portWasFree) return;
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], {
      env: makeEnv(tmpHome),
      timeout: 3000,
    });
    if (daemonProc?.exitCode === null) daemonProc.kill();
    if (tmpHome) cleanupDir(tmpHome);
  });

  // ── Auth gate (the actual #9 fix) ────────────────────────────────────────

  it('rejects /events with 403 when no auth token is provided', async ({ skip }) => {
    if (!portWasFree) skip();
    const status = await getEventsStatus(); // no token
    expect(status).toBe(403);
  });

  it('rejects /events with 403 on wrong token', async ({ skip }) => {
    if (!portWasFree) skip();
    const status = await getEventsStatus('not-the-real-token');
    expect(status).toBe(403);
  });

  it('accepts /events with the correct auth token', async ({ skip }) => {
    if (!portWasFree) skip();
    expect(authToken).toBeTruthy();
    const status = await getEventsStatus(authToken);
    expect(status).toBe(200);
  });

  // ── Init payload ─────────────────────────────────────────────────────────

  it('emits init event in the initial SSE payload', ({ skip }) => {
    if (!portWasFree) skip();
    expect(sseSnapshot.has('init')).toBe(true);
  });

  it('does NOT emit shields-status / decisions / csrf in init (retired in v3)', ({ skip }) => {
    if (!portWasFree) skip();
    // These three events backed the local browser dashboard (now removed).
    // Their absence is the regression guard.
    expect(sseSnapshot.has('shields-status')).toBe(false);
    expect(sseSnapshot.has('decisions')).toBe(false);
    expect(sseSnapshot.has('csrf')).toBe(false);
  });
});

// ── POST /decision idempotency ─────────────────────────────────────────────────

describe('daemon POST /decision — idempotency', () => {
  let tmpHome: string;
  let daemonProc: ChildProcess;
  let portWasFree = false;
  let csrfToken = '';

  beforeAll(async () => {
    portWasFree = await isPortFree(DAEMON_PORT);
    if (!portWasFree) return;

    tmpHome = makeTempHome();
    daemonProc = spawn(process.execPath, [CLI, 'daemon', 'start'], {
      env: makeEnv(tmpHome),
      stdio: 'pipe',
    });

    const ready = await waitForDaemon(6000);
    if (!ready) {
      daemonProc.kill();
      throw new Error('Daemon did not start within 6s');
    }

    // Read the per-process auth token straight from the PID file.
    // Pre-v3-sprint-#9 this used to come from a 'csrf' event on the SSE
    // stream; that emission was retired with the browser dashboard.
    csrfToken = readDaemonAuthToken(tmpHome);
  }, 10_000);

  afterAll(() => {
    if (!portWasFree) return;
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], {
      env: makeEnv(tmpHome),
      timeout: 3000,
    });
    if (daemonProc?.exitCode === null) daemonProc.kill(); // fallback: only if still running
    if (tmpHome) cleanupDir(tmpHome);
  });

  it('second POST /decision returns 409 with the first decision (first write wins)', async ({
    skip,
  }) => {
    if (!portWasFree) skip();
    expect(csrfToken, 'csrf token must be available').toBeTruthy();

    // No /wait consumer needed: the daemon's abandon timer only fires when an
    // SSE connection *closes* while pending.size > 0 — it is not triggered here
    // because no SSE client connects during this test. Entries added via
    // POST /check after beforeAll's SSE stream closed are safe from eviction.
    const checkRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ toolName: 'bash', args: { command: 'echo test' } }),
    });
    expect(checkRes.ok).toBe(true);
    const checkBody: unknown = await checkRes.json();
    expect(checkBody).toMatchObject({ id: expect.any(String) });
    const { id } = checkBody as { id: string };

    // First POST /decision → 200
    const d1 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(d1.status).toBe(200);

    // Second POST /decision (different decision) → 409, first decision preserved
    const d2 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'deny' }),
    });
    expect(d2.status).toBe(409);
    const body: unknown = await d2.json();
    // toMatchObject gives a clear failure message if the shape is wrong —
    // an unchecked `as` cast would silently pass with a malformed response.
    expect(body).toMatchObject({ conflict: true, decision: 'allow' }); // first write wins
  });

  it('same decision sent twice also returns 409 (allow→allow)', async ({ skip }) => {
    if (!portWasFree) skip();

    const checkRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ toolName: 'bash', args: { command: 'echo idempotent' } }),
    });
    const checkBody: unknown = await checkRes.json();
    expect(checkBody).toMatchObject({ id: expect.any(String) });
    const { id } = checkBody as { id: string };

    const d1 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(d1.status).toBe(200);

    // Same decision a second time — still 409; the first write always wins
    const d2 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(d2.status).toBe(409);
    const body: unknown = await d2.json();
    expect(body).toMatchObject({ decision: 'allow' });
  });

  it('first POST /decision with deny also returns 409 on second call', async ({ skip }) => {
    if (!portWasFree) skip();

    const checkRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ toolName: 'bash', args: { command: 'echo test2' } }),
    });
    const checkBody: unknown = await checkRes.json();
    expect(checkBody).toMatchObject({ id: expect.any(String) });
    const { id } = checkBody as { id: string };

    const d1 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'deny' }),
    });
    expect(d1.status).toBe(200);

    const d2 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(d2.status).toBe(409);
    const body: unknown = await d2.json();
    expect(body).toMatchObject({ decision: 'deny' });
  });

  it('POST /decision with an unknown id returns 404', async ({ skip }) => {
    if (!portWasFree) skip();
    // A UUID that was never registered via POST /check — must return 404, not 500.
    const res = await fetch(
      `http://127.0.0.1:${DAEMON_PORT}/decision/00000000-0000-0000-0000-000000000000`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
        body: JSON.stringify({ decision: 'allow' }),
      }
    );
    expect(res.status).toBe(404);
  });
});

// ── POST /decision source tracking ────────────────────────────────────────────
// Regression for: label always said "Browser Dashboard" regardless of which
// channel actually submitted the decision. Fix: POST /decision accepts an
// optional `source` field that is returned by GET /wait/:id.

describe('daemon POST /decision — source tracking', () => {
  let tmpHome: string;
  let daemonProc: ChildProcess;
  let portWasFree = false;
  let csrfToken = '';

  beforeAll(async () => {
    portWasFree = await isPortFree(DAEMON_PORT);
    if (!portWasFree) return;

    tmpHome = makeTempHome();
    daemonProc = spawn(process.execPath, [CLI, 'daemon', 'start'], {
      env: makeEnv(tmpHome),
      stdio: 'pipe',
    });

    const ready = await waitForDaemon(6000);
    if (!ready) {
      daemonProc.kill();
      throw new Error('Daemon did not start within 6s');
    }

    csrfToken = readDaemonAuthToken(tmpHome);
  }, 10_000);

  afterAll(() => {
    if (!portWasFree) return;
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], {
      env: makeEnv(tmpHome),
      timeout: 3000,
    });
    if (daemonProc?.exitCode === null) daemonProc.kill(); // fallback: only if still running
    if (tmpHome) cleanupDir(tmpHome);
  });

  async function registerEntry(label: string): Promise<string> {
    const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ toolName: 'bash', args: { command: `echo register-${label}` } }),
    });
    const { id } = (await res.json()) as { id: string };
    return id;
  }

  it('GET /wait returns source=terminal when POST /decision included source:terminal', async ({
    skip,
  }) => {
    if (!portWasFree) skip();
    expect(csrfToken).toBeTruthy();

    const id = await registerEntry('source-terminal');

    // POST decision with source before GET /wait connects (earlyDecision path)
    await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'deny', source: 'terminal' }),
    });

    const waitRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/wait/${id}`);
    expect(waitRes.ok).toBe(true);
    const body = (await waitRes.json()) as { decision: string; source?: string };
    expect(body.decision).toBe('deny');
    expect(body.source).toBe('terminal');
  });

  it('GET /wait returns source=browser when POST /decision included source:browser', async ({
    skip,
  }) => {
    if (!portWasFree) skip();

    const id = await registerEntry('source-browser');

    await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'allow', source: 'browser' }),
    });

    const waitRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/wait/${id}`);
    const body = (await waitRes.json()) as { decision: string; source?: string };
    expect(body.decision).toBe('allow');
    expect(body.source).toBe('browser');
  });

  it('GET /wait returns no source field when POST /decision omits source', async ({ skip }) => {
    if (!portWasFree) skip();

    const id = await registerEntry('source-omitted');

    await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'deny' }),
    });

    const waitRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/wait/${id}`);
    const body = (await waitRes.json()) as { decision: string; source?: string };
    expect(body.decision).toBe('deny');
    expect(body.source).toBeUndefined();
  });

  it('POST /decision with invalid source value is ignored (source not stored)', async ({
    skip,
  }) => {
    if (!portWasFree) skip();

    const id = await registerEntry('source-invalid');

    await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'allow', source: 'injected-value' }),
    });

    const waitRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/wait/${id}`);
    const body = (await waitRes.json()) as { decision: string; source?: string };
    expect(body.decision).toBe('allow');
    expect(body.source).toBeUndefined(); // invalid source silently dropped
  });

  // source field injection boundary: non-string and prototype-pollution attempts
  // must be rejected — the implementation uses a VALID_SOURCES allowlist Set,
  // these tests make the boundary explicit.
  it.each([
    ['null', null],
    ['number', 123],
    ['object', { __proto__: { polluted: true } }],
  ])('POST /decision with source:%s does not store a source value', async (label, sourceValue) => {
    if (!portWasFree) return; // port busy — daemon describe skips entirely

    const id = await registerEntry(`source-type-${label}`);

    await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'allow', source: sourceValue }),
    });

    const waitRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/wait/${id}`);
    const body = (await waitRes.json()) as { decision: string; source?: string };
    expect(body.decision).toBe('allow');
    expect(body.source).toBeUndefined();
  });

  it('POST /decision without CSRF token returns 403', async ({ skip }) => {
    if (!portWasFree) skip();

    const id = await registerEntry('csrf-missing');

    const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }, // no X-Node9-Token
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(res.status).toBe(403);
  });

  it('POST /decision with wrong CSRF token returns 403', async ({ skip }) => {
    if (!portWasFree) skip();

    const id = await registerEntry('csrf-wrong');

    const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': 'wrong-token' },
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(res.status).toBe(403);
  });

  // Regression: POST /check with slackDelegated:true must NOT trigger the
  // background authorizeHeadless call — that would create a duplicate cloud
  // request (cloudRequestId2) that never gets resolved in Mission Control.
  it('POST /check with slackDelegated:true creates entry but skips background auth', async ({
    skip,
  }) => {
    if (!portWasFree) skip();

    const checkRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolName: 'bash',
        args: { command: 'git push' },
        slackDelegated: true,
      }),
    });
    expect(checkRes.ok).toBe(true);
    const { id } = (await checkRes.json()) as { id: string };
    expect(id).toBeTruthy();

    // Give the daemon 500ms to run any background work — if background auth ran,
    // it would resolve the entry immediately (audit mode auto-approves). The entry
    // must stay pending because slackDelegated skips background auth entirely.
    await new Promise((r) => setTimeout(r, 500));

    // Resolve via /decision so GET /wait doesn't hang the test
    const d = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': csrfToken },
      body: JSON.stringify({ decision: 'deny' }),
    });
    // If the entry was already auto-resolved by background auth, /decision returns 409.
    // It must return 200 — the entry was still pending (background auth was skipped).
    expect(d.status).toBe(200);
  });
});

// POST /suggestions/:id/apply — entire route + suggestion-engine surface
// removed in v3 browser-removal sprint. The path-traversal guard test
// suite previously here is no longer applicable; the route returns 404.

// ── DNS rebinding guard ────────────────────────────────────────────────────────
// Regression: daemon must reject requests with a Host header that doesn't match
// 127.0.0.1:PORT or localhost:PORT. A DNS-rebinding attack sets Host: attacker.com
// (which resolves to 127.0.0.1) — without this guard the attacker could read the
// CSRF token from /events and make authenticated requests.

describe('daemon DNS rebinding guard', () => {
  let tmpHome: string;
  let daemonProc: ChildProcess;
  let portWasFree = false;

  beforeAll(async () => {
    portWasFree = await isPortFree(DAEMON_PORT);
    if (!portWasFree) return;

    tmpHome = makeTempHome();
    daemonProc = spawn(process.execPath, [CLI, 'daemon', 'start'], {
      env: makeEnv(tmpHome),
      stdio: 'pipe',
    });

    const ready = await waitForDaemon(6000);
    if (!ready) {
      daemonProc.kill();
      throw new Error('Daemon did not start within 6s');
    }
  }, 15_000);

  afterAll(() => {
    if (!portWasFree) return;
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], {
      env: makeEnv(tmpHome),
      timeout: 3000,
    });
    if (daemonProc?.exitCode === null) daemonProc.kill();
    if (tmpHome) cleanupDir(tmpHome);
  });

  it('rejects requests with a spoofed Host header (421)', async ({ skip }) => {
    if (!portWasFree) skip();

    // fetch() silently ignores custom Host header overrides (undici sets Host
    // from the URL). Use http.request() directly so the spoofed header is
    // actually sent on the wire — this is what a DNS-rebinding attack does.
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: DAEMON_PORT,
          path: '/settings',
          method: 'GET',
          headers: { Host: 'attacker.com' },
        },
        (res) => {
          resolve(res.statusCode ?? 0);
          res.resume();
        }
      );
      req.on('error', reject);
      req.end();
    });
    expect(status).toBe(421);
  });

  it('accepts requests with Host: 127.0.0.1:PORT (200)', async ({ skip }) => {
    if (!portWasFree) skip();

    const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/settings`, {
      headers: { Host: `127.0.0.1:${DAEMON_PORT}` },
    });
    expect(res.ok).toBe(true);
  });

  it('accepts requests with Host: localhost:PORT (200)', async ({ skip }) => {
    if (!portWasFree) skip();

    const res = await fetch(`http://localhost:${DAEMON_PORT}/settings`, {
      headers: { Host: `localhost:${DAEMON_PORT}` },
    });
    expect(res.ok).toBe(true);
  });
});
