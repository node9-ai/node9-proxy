/**
 * R0: a spawn that fails to EXEC must be recorded as a failed start.
 *
 * This exists because the first attempt at that was unreachable code. It recorded
 * `spawn-failed` from a try/catch around spawn() — but spawn() does not throw for
 * exec failures; it reports them asynchronously on the child's 'error' event:
 *
 *   spawn('/definitely/not/a/real/binary') → NO THROW; async 'error' event: ENOENT
 *   spawn('<non-executable file>')          → NO THROW; async 'error' event: EACCES
 *
 * So the catch only ever fired for a synchronous TypeError from bad arguments, and
 * the stranded-'starting' bug it was written to fix survived four review rounds and
 * a /review-pr — green the whole way, because nothing exercised it.
 *
 * The test therefore drives the REAL 'error' event. A mocked throw would pass
 * against the old unreachable catch and recreate the same false witness. It also
 * proves the listener is attached at all: emitting 'error' on an EventEmitter with
 * no listener throws, so a regression here fails loudly rather than silently.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EventEmitter } from 'events';
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { autoStartDaemonAndWait } from '../cli/daemon-starter';
import { readStartupState, recordStartupState } from '../daemon/startup-log';

// ESM exports are not configurable, so spawn cannot be spied — mock the module
// (the convention already used in observe-mode.spec.ts / core.test.ts).
vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>();
  return { ...actual, spawn: vi.fn() };
});
const mockSpawn = vi.mocked(spawn);

// The poll loop calls these; R1 needs isDaemonReachable to throw mid-poll.
const { mockIsRunning, mockIsReachable } = vi.hoisted(() => ({
  mockIsRunning: vi.fn(() => false),
  mockIsReachable: vi.fn(async () => false),
}));
vi.mock('../auth/daemon', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/daemon')>();
  return { ...actual, isDaemonRunning: mockIsRunning, isDaemonReachable: mockIsReachable };
});

let tmp: string;
let homeSpy: ReturnType<typeof vi.spyOn>;
let origArgv1: string;
let origTesting: string | undefined;

beforeEach(() => {
  mockIsRunning.mockReturnValue(false);
  mockIsReachable.mockResolvedValue(false);
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-spawnerr-'));
  fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
  homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmp);
  // autoStartDaemonAndWait bails unless argv[1] is an absolute, real .js file, and
  // returns early in testing mode — neither is about the behaviour under test.
  origArgv1 = process.argv[1];
  process.argv[1] = path.resolve(__dirname, '../../dist/cli.js');
  origTesting = process.env.NODE9_TESTING;
  delete process.env.NODE9_TESTING;
});
afterEach(() => {
  vi.restoreAllMocks();
  homeSpy.mockRestore();
  process.argv[1] = origArgv1;
  if (origTesting !== undefined) process.env.NODE9_TESTING = origTesting;
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** A stand-in child that reports an exec failure the way Node really does. */
function fakeChildEmittingError(code: string) {
  const child = new EventEmitter() as EventEmitter & { unref: () => void };
  child.unref = () => {};
  mockSpawn.mockImplementation(() => {
    // Node surfaces exec failures on a later tick, never synchronously.
    setTimeout(
      () => child.emit('error', Object.assign(new Error(`${code}: spawn failed`), { code })),
      0
    );
    return child as unknown as ReturnType<typeof spawn>;
  });
  return child;
}

describe('R0 — an exec failure is recorded, not swallowed', () => {
  it('records spawn-failed when the child emits ENOENT', async () => {
    fakeChildEmittingError('ENOENT');
    const started = await autoStartDaemonAndWait();

    expect(started).toBe(false);
    const state = readStartupState();
    expect(state?.outcome).toBe('failed');
    expect(state?.kind).toBe('spawn-failed');
    expect(state?.detail).toMatch(/ENOENT/);
  });

  it('records spawn-failed when the child emits EMFILE (the realistic case here)', async () => {
    // The spawn target is process.execPath — the running node binary — so ENOENT
    // and EACCES are near-impossible at this call site. Resource exhaustion is the
    // failure that actually reaches it on a loaded machine.
    fakeChildEmittingError('EMFILE');
    await autoStartDaemonAndWait();
    expect(readStartupState()?.kind).toBe('spawn-failed');
    expect(readStartupState()?.detail).toMatch(/EMFILE/);
  });

  it('leaves the marker at "starting" when the child spawns cleanly', async () => {
    // No 'error' event: the child now owns the outcome and will record 'ok' or
    // 'failed' itself. The spawner must not pre-empt that.
    const child = new EventEmitter() as EventEmitter & { unref: () => void };
    child.unref = () => {};
    mockSpawn.mockReturnValue(child as unknown as ReturnType<typeof spawn>);
    await autoStartDaemonAndWait();
    expect(readStartupState()?.outcome).toBe('starting');
  });
});

describe('R1 — only a spawn that produced no child may blame the attempt', () => {
  it('does not overwrite the daemon\'s own "ok" when the POLL throws', async () => {
    // The catch wraps the poll loop as well as the spawn. A throw from polling is
    // not a spawn failure, and by then the child is authoritative — it has already
    // recorded its own outcome. Overwriting that leaves the state claiming failure
    // for a daemon that is up.
    const child = new EventEmitter() as EventEmitter & { unref: () => void };
    child.unref = () => {};
    mockSpawn.mockReturnValue(child as unknown as ReturnType<typeof spawn>);
    // Model the real ordering: the spawner marks 'starting', then the CHILD comes
    // up and records its own 'ok' while we are polling — and only then does the
    // probe throw. (Seeding 'ok' before the call would be wrong: the spawner's own
    // 'starting' legitimately overwrites anything older.)
    mockIsRunning.mockImplementation(() => {
      recordStartupState('ok'); // the child, mid-poll
      return true;
    });
    mockIsReachable.mockRejectedValue(new Error('ECONNRESET while probing'));

    await autoStartDaemonAndWait();

    expect(readStartupState()?.outcome).toBe('ok');
    expect(readStartupState()?.kind).toBeUndefined();
  });
});
