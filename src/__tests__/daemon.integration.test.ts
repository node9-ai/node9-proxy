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
    if ((e as NodeJS.ErrnoException).code !== 'EBUSY') throw e;
    console.warn(`[cleanupDir] EBUSY — temp dir leaked: ${dir}`);
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
 */
function readSseStream(timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    let settled = false;
    const done = (value: string) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    const req = http.get(`http://127.0.0.1:${DAEMON_PORT}/events`, (res) => {
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
    });
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

// ── shields-status emitted on SSE connect ─────────────────────────────────────
// Regression: shields-status was only broadcast on toggle (POST /shields/toggle).
// A freshly connected dashboard never received it and stayed on "Loading…" forever.
// Fix: emit shields-status in the GET /events initial payload alongside init and decisions.

describe('daemon /events — shields-status emitted on connect', () => {
  let tmpHome: string;
  let daemonProc: ChildProcess;
  // Captured once in beforeAll and shared across all tests — avoids 3 separate
  // 1.5s SSE connections and eliminates timing sensitivity on slow CI.
  let sseSnapshot: Map<string, unknown>;
  let portWasFree = false;

  beforeAll(async () => {
    portWasFree = await isPortFree(DAEMON_PORT);
    if (!portWasFree) return; // skip setup — tests will self-skip via ctx.skip()

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

      // Capture the initial SSE burst once — shared by all three tests below.
      // 3000ms gives slow CI enough headroom; the daemon flushes the initial
      // events synchronously so in practice this completes in <100ms.
      const raw = await readSseStream(3000);
      sseSnapshot = parseSseEvents(raw);
    } catch (err) {
      // Ensure tmpHome is always cleaned up even if daemon startup throws,
      // so temp directories don't accumulate on CI on repeated failures.
      if (tmpHome) cleanupDir(tmpHome);
      throw err;
    }
  }, 15_000); // waitForDaemon(6s) + readSseStream(3s) = 9s minimum; 15s gives CI headroom

  afterAll(() => {
    if (!portWasFree) return;
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], {
      env: makeEnv(tmpHome),
      timeout: 3000,
    });
    if (daemonProc?.exitCode === null) daemonProc.kill(); // fallback: only if still running
    if (tmpHome) cleanupDir(tmpHome);
  });

  it('emits shields-status in the initial SSE payload', ({ skip }) => {
    // it.skipIf cannot be used here: the condition depends on beforeAll (async port
    // check), which runs after test collection. ctx.skip() is the correct way to
    // produce a visible skip in the Vitest report when setup was not possible.
    if (!portWasFree) skip();

    expect(
      sseSnapshot.has('shields-status'),
      `shields-status event must be present in initial SSE payload.\nGot events: ${[...sseSnapshot.keys()].join(', ')}`
    ).toBe(true);
  });

  it('shields-status payload lists all shields with correct active state', ({ skip }) => {
    if (!portWasFree) skip();

    // Assert defined before accessing .shields — gives a clear failure message
    // if test 1 is skipped or the event is absent (tests can run independently).
    const payload = sseSnapshot.get('shields-status') as
      | { shields: Array<{ name: string; description: string; active: boolean }> }
      | undefined;
    expect(payload, 'shields-status payload must be defined').toBeDefined();
    expect(Array.isArray(payload!.shields)).toBe(true);

    const { shields } = payload!;

    // Verify the one shield we configured active
    const filesystem = shields.find((s) => s.name === 'filesystem');
    expect(filesystem, 'filesystem shield must appear in payload').toBeDefined();
    expect(filesystem!.active).toBe(true); // configured active in shields.json

    // Verify all other known shields are inactive — enumerate structurally
    // rather than hardcoding names so this survives adding/removing shields.
    for (const s of shields) {
      expect(typeof s.name, `shield "${s.name}" must have a string name`).toBe('string');
      expect(typeof s.description, `shield "${s.name}" must have a string description`).toBe(
        'string'
      );
      if (s.name !== 'filesystem') {
        expect(s.active, `shield "${s.name}" should be inactive (not in shields.json)`).toBe(false);
      }
    }
  });

  it('init and decisions events are still present alongside shields-status', ({ skip }) => {
    if (!portWasFree) skip();

    expect(sseSnapshot.has('init'), 'init event must still be present').toBe(true);
    expect(sseSnapshot.has('decisions'), 'decisions event must still be present').toBe(true);
    expect(sseSnapshot.has('shields-status'), 'shields-status event must be present').toBe(true);
  });

  it('csrf token is emitted in the initial SSE payload', ({ skip }) => {
    if (!portWasFree) skip();

    expect(
      sseSnapshot.has('csrf'),
      `csrf event must be present in initial SSE payload.\nGot events: ${[...sseSnapshot.keys()].join(', ')}`
    ).toBe(true);
    const payload = sseSnapshot.get('csrf') as { token: string } | undefined;
    expect(payload?.token).toBeTruthy();
    expect(typeof payload?.token).toBe('string');
  });

  it('csrf token is the same across two SSE connections (re-emit, not regenerate)', async ({
    skip,
  }) => {
    if (!portWasFree) skip();

    const [raw1, raw2] = await Promise.all([readSseStream(1500), readSseStream(1500)]);
    const events1 = parseSseEvents(raw1);
    const events2 = parseSseEvents(raw2);
    const token1 = (events1.get('csrf') as { token: string } | undefined)?.token;
    const token2 = (events2.get('csrf') as { token: string } | undefined)?.token;
    expect(token1).toBeTruthy();
    // Token is process-lifetime (one UUID per daemon start), not per-SSE-session.
    // Threat model: the CSRF token prevents third-party web pages from submitting
    // decisions via XSS (they can't read the SSE stream cross-origin). A static
    // per-process token is sufficient because the daemon binds to 127.0.0.1 only
    // and dies when the user's shell session ends. Per-reconnect rotation would
    // break concurrent browser + tail sessions sharing the same daemon.
    expect(token1).toBe(token2);
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

    // Acquire CSRF token from SSE
    const raw = await readSseStream(1500);
    const events = parseSseEvents(raw);
    csrfToken = (events.get('csrf') as { token: string } | undefined)?.token ?? '';
  }, 15_000); // waitForDaemon(6s) + readSseStream(1.5s) = 7.5s minimum; 15s gives CI headroom

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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(d1.status).toBe(200);

    // Second POST /decision (different decision) → 409, first decision preserved
    const d2 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(d1.status).toBe(200);

    // Same decision a second time — still 409; the first write always wins
    const d2 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
      body: JSON.stringify({ decision: 'deny' }),
    });
    expect(d1.status).toBe(200);

    const d2 = await fetch(`http://127.0.0.1:${DAEMON_PORT}/decision/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
      body: JSON.stringify({ decision: 'allow' }),
    });
    expect(d2.status).toBe(409);
    const body: unknown = await d2.json();
    expect(body).toMatchObject({ decision: 'deny' });
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

    const raw = await readSseStream(1500);
    const events = parseSseEvents(raw);
    csrfToken = (events.get('csrf') as { token: string } | undefined)?.token ?? '';
  }, 15_000); // waitForDaemon(6s) + readSseStream(1.5s) = 7.5s minimum; 15s gives CI headroom

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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': 'wrong-token' },
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
      headers: { 'Content-Type': 'application/json', 'X-Node9-Token': csrfToken },
      body: JSON.stringify({ decision: 'deny' }),
    });
    // If the entry was already auto-resolved by background auth, /decision returns 409.
    // It must return 200 — the entry was still pending (background auth was skipped).
    expect(d.status).toBe(200);
  });
});
