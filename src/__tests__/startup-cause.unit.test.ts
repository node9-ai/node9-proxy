/**
 * B1: the daemon startup STATE — what doctor prints beneath "Daemon not running".
 *
 * An earlier design parsed daemon-startup.log (the raw stderr sink) to work this
 * out. Two review rounds found five separate ways the text lied: a crash dump's
 * last line is Node's version banner; `Error [ERR_REQUIRE_ESM]:` does not match
 * `Error:`; a SUCCESSFUL start looks like nothing at all, so an old crash was
 * reported forever; a multi-line err.message forges a second entry; and an
 * unrelated append refreshes the mtime that recency was judged on.
 *
 * All five were one root cause — a single file serving both a machine and a human
 * — so the machine signal moved to its own atomically-written JSON object. What
 * follows is what is left to get wrong.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  logDaemonStartup,
  readStartupCause,
  readStartupState,
  recordStartupState,
  DAEMON_STARTUP_STATE,
} from '../daemon/startup-log';

let tmp: string;
let homeSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-cause-'));
  homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmp);
});
afterEach(() => {
  homeSpy.mockRestore();
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** Seed a state whose age we control — recency is judged per state object. */
const seed = (state: object, msAgo = 60_000) => {
  fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
  fs.writeFileSync(
    DAEMON_STARTUP_STATE(),
    JSON.stringify({ at: new Date(Date.now() - msAgo).toISOString(), ...state }),
    'utf-8'
  );
};

describe('recordStartupState', () => {
  it('creates .node9 if absent and round-trips through readStartupState', () => {
    recordStartupState('failed', 'bind-failed', 'EACCES');
    const s = readStartupState();
    expect(s?.outcome).toBe('failed');
    expect(s?.kind).toBe('bind-failed');
    expect(s?.detail).toBe('EACCES');
  });

  it('overwrites rather than appends — only the latest attempt matters', () => {
    recordStartupState('failed', 'startup-throw', 'boom');
    recordStartupState('ok');
    expect(readStartupState()?.outcome).toBe('ok');
    expect(readStartupState()?.kind).toBeUndefined(); // no residue from the failure
  });

  it('survives a multi-line detail without forging a second entry', () => {
    // The line-oriented format this replaced could not: a detail containing
    // "\nError: connect ECONNREFUSED" was read back as a DIFFERENT, nested error,
    // losing both the real classification and its timestamp.
    recordStartupState(
      'failed',
      'startup-throw',
      'Cannot find module X\nRequire stack:\n- /a/cli.js\nError: connect ECONNREFUSED'
    );
    const cause = readStartupCause();
    expect(cause?.kind).toBe('startup-throw'); // not "Error"
    expect(cause?.detail).toMatch(/Cannot find module X/);
  });

  it('truncates a pathologically long detail', () => {
    recordStartupState('failed', 'startup-throw', 'y'.repeat(5000));
    expect(readStartupState()!.detail!.length).toBeLessThanOrEqual(200);
  });

  it('never throws when the state path is unwritable', () => {
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.mkdirSync(DAEMON_STARTUP_STATE()); // a directory where the file should be
    expect(() => recordStartupState('ok')).not.toThrow();
    expect(readStartupState()).toBeNull();
  });
});

describe('readStartupCause — a successful start means there is nothing to explain', () => {
  it('says nothing after a clean start', () => {
    seed({ outcome: 'ok' });
    expect(readStartupCause()).toBeNull();
  });

  it('says nothing when the start stood down for a healthy daemon', () => {
    // "another daemon owns the port" printed beneath "Daemon not running" would
    // assert the opposite of the warning it is meant to explain.
    seed({ outcome: 'ok-elsewhere' });
    expect(readStartupCause()).toBeNull();
  });

  it('a success ERASES an earlier failure — no resurrection', () => {
    // The bug that survived an entire review round: on an append-only log an old
    // crash stayed the newest recognisable entry forever, so doctor blamed an
    // ERR_REQUIRE_ESM that had not happened in weeks.
    recordStartupState('failed', 'startup-throw', 'ancient boom');
    recordStartupState('ok');
    expect(readStartupCause()).toBeNull();
  });
});

describe('readStartupCause — a real failure is reported', () => {
  it('reports a recorded failure with its kind and detail', () => {
    seed({ outcome: 'failed', kind: 'bind-failed', detail: 'EACCES' });
    const cause = readStartupCause();
    expect(cause?.kind).toBe('bind-failed');
    expect(cause?.detail).toBe('EACCES');
  });

  it('reports an unidentified port squatter — the silent-loop case', () => {
    // Something holds the port but no pid file names it, so every CLI reports
    // "not running" while each new start exits 0 and says nothing. Recording this
    // as benign (an earlier design did) hides an unbounded loop.
    seed({
      outcome: 'failed',
      kind: 'orphan-unidentified',
      detail: 'another process holds :7391 but could not be identified',
    });
    expect(readStartupCause()?.kind).toBe('orphan-unidentified');
  });

  it('stays quiet while a start is still in progress', () => {
    // A daemon needs a moment to bind. Accusing "did not start" inside that window
    // would be a false alarm on a perfectly healthy start.
    seed({ outcome: 'starting' }, 2_000);
    expect(readStartupCause()).toBeNull();
  });

  it('reports a spawn that never reported back — the import-time crash', () => {
    // THE incident: the child dies at module load, before it runs a line of our
    // code, so it cannot record anything itself. The marker written before the
    // spawn is the only evidence the attempt ever happened. Aged past the
    // still-booting grace so it counts as died, not slow.
    seed({ outcome: 'starting' }, 10 * 60 * 1000);
    const cause = readStartupCause();
    expect(cause?.kind).toBe('did-not-start');
    expect(cause?.detail).toMatch(/daemon-startup\.log/); // points at the human artifact
  });

  it('does not claim the daemon EXITED — it may never have started at all', () => {
    // A stranded 'starting' has two causes: the child crashed at module load, or no
    // child was ever created (an exec failure on the check path, which deliberately
    // records nothing — see daemon-starter/check R0). "exited during startup" is
    // true only for the first, and points at a log that is empty for the second.
    seed({ outcome: 'starting' }, 10 * 60 * 1000);
    const detail = readStartupCause()!.detail;
    expect(detail).not.toMatch(/exited/);
    expect(detail).toMatch(/hook-debug\.log/); // names the other place evidence can be
  });
});

describe('readStartupCause — says nothing rather than something wrong', () => {
  it('ignores a state older than the recency window', () => {
    seed({ outcome: 'failed', kind: 'startup-throw' }, 48 * 60 * 60 * 1000);
    expect(readStartupCause()).toBeNull();
  });

  it('honours a caller-supplied window', () => {
    seed({ outcome: 'failed', kind: 'startup-throw' }, 2 * 60 * 60 * 1000);
    expect(readStartupCause(60 * 60 * 1000)).toBeNull();
    expect(readStartupCause(4 * 60 * 60 * 1000)?.kind).toBe('startup-throw');
  });

  it('recency uses the state timestamp, NOT the file mtime', () => {
    // The distinction that broke the log-based design: touching the file must not
    // make an old failure look current.
    seed({ outcome: 'failed', kind: 'startup-throw' }, 48 * 60 * 60 * 1000);
    const now = new Date();
    fs.utimesSync(DAEMON_STARTUP_STATE(), now, now); // fresh mtime, stale content
    expect(readStartupCause()).toBeNull();
  });

  it('returns null for missing, corrupt, empty or malformed state', () => {
    expect(readStartupCause()).toBeNull(); // absent
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.writeFileSync(DAEMON_STARTUP_STATE(), 'not json{', 'utf-8');
    expect(readStartupCause()).toBeNull();
    fs.writeFileSync(DAEMON_STARTUP_STATE(), '', 'utf-8');
    expect(readStartupCause()).toBeNull();
    fs.writeFileSync(DAEMON_STARTUP_STATE(), JSON.stringify({ outcome: 'ok' }), 'utf-8'); // no `at`
    expect(readStartupCause()).toBeNull();
  });

  it('returns null for an unknown outcome from a newer version', () => {
    seed({ outcome: 'some-future-thing' });
    expect(readStartupCause()).toBeNull();
  });

  it('returns null for a non-ISO timestamp', () => {
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.writeFileSync(
      DAEMON_STARTUP_STATE(),
      JSON.stringify({ outcome: 'failed', kind: 'x', at: 'yesterday-ish' }),
      'utf-8'
    );
    expect(readStartupCause()).toBeNull();
  });
});

describe('recordStartupState — a failing streak keeps its FIRST timestamp', () => {
  it('does not reset the clock when re-marked during a crash loop', () => {
    // The hook fires on every tool call, so a crash-looping daemon is re-marked
    // every few seconds. If each mark reset the timestamp, the grace window would
    // never expire and doctor would stay silent for as long as the user kept
    // working — hiding the loop most reliably exactly when it hurts most.
    seed({ outcome: 'starting' }, 10 * 60 * 1000);
    // Read the seeded value back rather than recomputing it: two Date.now() calls
    // can straddle a millisecond boundary, which made this assertion flaky.
    const first = readStartupState()!.at;
    recordStartupState('starting'); // a later hook invocation
    expect(readStartupState()?.at).toBe(first);
    expect(readStartupCause()?.kind).toBe('did-not-start'); // still reported
  });

  it('starts a fresh streak after a conclusive outcome', () => {
    recordStartupState('starting');
    recordStartupState('ok'); // streak resolved
    recordStartupState('starting'); // a genuinely new attempt
    expect(readStartupState()?.outcome).toBe('starting');
    expect(Date.now() - new Date(readStartupState()!.at).getTime()).toBeLessThan(5_000);
  });

  it('re-marks when the previous streak has aged out of the window', () => {
    // Otherwise an ancient 'starting' would silence us for the opposite reason.
    seed({ outcome: 'starting' }, 48 * 60 * 60 * 1000);
    recordStartupState('starting');
    expect(Date.now() - new Date(readStartupState()!.at).getTime()).toBeLessThan(5_000);
  });

  it('records a spawn that threw as a conclusive failure, not a stranded marker', () => {
    // No child ever existed, so nothing else will resolve 'starting'. Left alone it
    // reads as "the daemon exited during startup — see daemon-startup.log", which
    // points at a file holding no trace of a process that was never created.
    recordStartupState('starting');
    recordStartupState('failed', 'spawn-failed', 'EACCES');
    const cause = readStartupCause();
    expect(cause?.kind).toBe('spawn-failed');
    expect(cause?.detail).toBe('EACCES');
  });
});

describe('round 5 — regressions found by the fifth review', () => {
  it('does not truncate the human log when recording a breadcrumb (evidence survives)', () => {
    // The crashing daemon writes its stack to stderr, which the spawner redirects
    // into this file, and THEN calls logDaemonStartup. Capping there wiped the
    // stack milliseconds after it landed, leaving doctor pointing at an empty log.
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    const log = path.join(tmp, '.node9', 'daemon-startup.log');
    fs.writeFileSync(log, 'x'.repeat(300 * 1024) + '\nError: the stack that matters\n');
    logDaemonStartup('startup-throw', 'boom');
    const after = fs.readFileSync(log, 'utf-8');
    expect(after).toMatch(/the stack that matters/);
    expect(after).toMatch(/daemon-startup:startup-throw/);
  });

  it('is not pinned forever by a FUTURE-dated streak timestamp', () => {
    // `Date.now() - prevAt < 24h` is also true when prevAt is in the future (clock
    // skew, a corrected clock), which pinned the marker permanently and silenced
    // every later attempt.
    seed({ outcome: 'starting' }, -48 * 60 * 60 * 1000); // 48h in the FUTURE
    recordStartupState('starting');
    const at = new Date(readStartupState()!.at).getTime();
    expect(Math.abs(Date.now() - at)).toBeLessThan(5_000); // re-stamped to now
  });

  it('labels a failing streak by when it STARTED, not as the last attempt', () => {
    // The timestamp is deliberately the first attempt of the streak, so calling it
    // "last start attempt" misreports the age by the length of the streak.
    seed({ outcome: 'starting' }, 10 * 60 * 1000);
    expect(readStartupCause()?.label).toBe('start attempts failing since');
    seed({ outcome: 'failed', kind: 'bind-failed' });
    expect(readStartupCause()?.label).toBe('last start attempt');
  });
});
