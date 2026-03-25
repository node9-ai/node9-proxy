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

function cleanupDir(dir: string) {
  fs.rmSync(dir, { recursive: true, force: true });
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
        env: { ...process.env, HOME: tmpHome, NODE9_TESTING: '1' },
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
  });

  afterAll(() => {
    if (!portWasFree) return;
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], {
      env: { ...process.env, HOME: tmpHome, NODE9_TESTING: '1' },
      timeout: 3000,
    });
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
});
