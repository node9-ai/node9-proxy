// src/daemon/startup-log.ts
// Daemon startup diagnostics, in two deliberately separate halves:
//
//   daemon-startup.log        HUMAN artifact. Whatever the child wrote to stderr,
//                             plus one-line breadcrumbs. NOTHING parses it.
//   daemon-startup-state.json MACHINE signal. One atomically-overwritten object
//                             that `doctor` reads to explain a down daemon.
//
// They were one file once. Every review round found another way the mixed text
// lied, because a log is written for people and a diagnostic is read by code.
// Best-effort throughout — diagnostics must never break daemon startup or the
// enforcement hot path.
import fs from 'fs';
import path from 'path';
import os from 'os';

export const DAEMON_STARTUP_LOG = () => path.join(os.homedir(), '.node9', 'daemon-startup.log');

// A daemon that crash-loops (the exact incident: ERR_REQUIRE_ESM at import) gets
// re-spawned on many tool calls, each appending its startup stderr here. Cap the
// file so that loop can't grow it without bound (old code discarded stderr entirely).
const MAX_STARTUP_LOG_BYTES = 256 * 1024;

/** Keep the human log bounded. Called from BOTH writers: the spawner opens it as
 *  an fd, while a systemd-launched daemon never goes through the spawner at all, so
 *  neither one alone is enough. Never throws. */
function capStartupLog(file: string): void {
  try {
    if (fs.statSync(file).size > MAX_STARTUP_LOG_BYTES) fs.truncateSync(file);
  } catch {
    /* absent → nothing to truncate */
  }
}

/**
 * Open daemon-startup.log (append) for a spawned daemon's stderr — creating ~/.node9
 * if absent and truncating first if the file grew past the cap. Returns an fd the
 * CALLER MUST close (in a finally), or undefined to fall back to discarding stderr.
 * Never throws.
 */
export function openStartupLogFd(): number | undefined {
  try {
    const file = DAEMON_STARTUP_LOG();
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    capStartupLog(file);
    return fs.openSync(file, 'a');
  } catch {
    return undefined;
  }
}

// ── Startup STATE (the machine-readable half) ────────────────────────────────
//
// daemon-startup.log above is a HUMAN artifact: it holds whatever the child wrote
// to stderr, in whatever shape, from any number of concurrent starts. Nothing
// parses it — an earlier design did, and every review round found another way the
// text lied (a crash dump's last line is Node's version banner; `Error [CODE]:`
// does not match `Error:`; a successful start looks like nothing at all; a
// multi-line err.message forges an entry; an old line resurfaces whenever an
// unrelated append refreshes the file's mtime).
//
// The machine signal lives here instead: ONE small JSON object, atomically
// overwritten, carrying its own timestamp. No ordering, no shapes, no parsing.

/** Where the last start attempt got to. */
export type StartupOutcome =
  /** a spawn was issued and has not reported back — if the daemon is also down,
   *  the child died before it could run any of its own code (the ERR_REQUIRE_ESM
   *  class of crash, which happens at module load and no try/catch can observe) */
  | 'starting'
  /** bound the port and is serving */
  | 'ok'
  /** found a healthy daemon already running and stood down */
  | 'ok-elsewhere'
  /** reached its own code and failed there */
  | 'failed';

export interface StartupState {
  outcome: StartupOutcome;
  kind?: string;
  detail?: string;
  /** ISO-8601. The state's OWN time — never the file's mtime. */
  at: string;
}

export const DAEMON_STARTUP_STATE = () =>
  path.join(os.homedir(), '.node9', 'daemon-startup-state.json');

/** doctor's output is a scannable list, not a log viewer. */
const MAX_DETAIL = 200;
/** How long a 'starting' marker is treated as "still booting" rather than "died".
 *
 *  The polling spawner gives up after 5s, but the `check` hot path does NOT poll —
 *  it spawns and returns — so nothing bounds how slow a healthy start may be on a
 *  loaded machine. Exposure is limited because the only caller reads this from
 *  doctor's daemon-DOWN branch (a start that eventually succeeded is never
 *  described), but the window is generous anyway: over-reporting "did not start"
 *  for a daemon that is merely slow is the same class of lie this whole feature
 *  exists to avoid. */
const STARTING_GRACE_MS = 90 * 1000;

/**
 * Record where this start attempt got to. Overwrites — only the latest matters.
 * Atomic (temp + rename) so a concurrent reader never sees a half-written object.
 * Never throws: diagnostics must not break daemon startup or the check hot path.
 */
export function recordStartupState(outcome: StartupOutcome, kind?: string, detail?: string): void {
  try {
    // Keep the FIRST attempt of a failing streak. The hook fires on every tool
    // call, so a crash-looping daemon gets re-marked every few seconds; if each
    // one reset the clock, the grace window below would never expire and doctor
    // would stay silent for exactly as long as the user kept working — the busier
    // the session, the more reliably the crash loop is hidden. A streak ends when
    // something conclusive ('ok' / 'failed') overwrites it.
    if (outcome === 'starting') {
      const prev = readStartupState();
      if (prev?.outcome === 'starting') {
        const prevAt = new Date(prev.at).getTime();
        // …unless the streak is itself ancient, in which case it has already aged
        // out of the reporting window and would silence us for the opposite reason.
        // Math.abs, not a bare subtraction: a FUTURE-dated timestamp (clock skew, a
        // corrected system clock, a hand-edited file) makes `now - prevAt` negative,
        // which passes a `< 24h` test forever — pinning the marker permanently and
        // silencing every later attempt.
        const age = Math.abs(Date.now() - prevAt);
        if (!isNaN(prevAt) && age < 24 * 60 * 60 * 1000) return;
      }
    }
    const file = DAEMON_STARTUP_STATE();
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const state: StartupState = { outcome, at: new Date().toISOString() };
    if (kind) state.kind = kind;
    // JSON escapes newlines, so a multi-line err.message can no longer forge a
    // second entry — the whole class of bug that came from a line-oriented format.
    if (detail) state.detail = detail.slice(0, MAX_DETAIL);
    const tmp = `${file}.${process.pid}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(state), 'utf-8');
      fs.renameSync(tmp, file);
    } catch (err) {
      try {
        fs.unlinkSync(tmp);
      } catch {
        /* may not exist */
      }
      throw err;
    }
  } catch {
    /* best-effort */
  }
}

/** Read the raw state object. Never throws; returns null if absent or corrupt. */
export function readStartupState(): StartupState | null {
  try {
    const raw = fs.readFileSync(DAEMON_STARTUP_STATE(), 'utf-8');
    const s = JSON.parse(raw) as StartupState;
    if (!s || typeof s.outcome !== 'string' || typeof s.at !== 'string') return null;
    return s;
  } catch {
    return null;
  }
}

/** What `doctor` prints beneath "Daemon not running" to explain it.
 *  `label` exists because `at` does not always mean the same thing: for a failing
 *  streak it is the FIRST attempt (preserved so the grace window can expire), so
 *  calling it "last start attempt" would misreport the age by the length of the
 *  streak. Each outcome names its own timestamp. */
export type StartupCause = { kind: string; detail: string; at: Date; label: string } | null;

/**
 * Why the last start attempt did not leave a daemon running — or null if there is
 * nothing honest to say.
 *
 * Only meaningful when the daemon is in fact down; `doctor` calls it from that
 * branch. Returns null rather than guessing: a wrong cause under "Daemon not
 * running" sends someone down the wrong path, which is worse than silence.
 */
export function readStartupCause(maxAgeMs = 24 * 60 * 60 * 1000): StartupCause {
  const s = readStartupState();
  if (!s) return null;
  const at = new Date(s.at);
  // Recency judged on the state's own timestamp — the reason this is a state file
  // and not a log tail.
  if (isNaN(at.getTime()) || Date.now() - at.getTime() > maxAgeMs) return null;

  switch (s.outcome) {
    case 'ok':
    case 'ok-elsewhere':
      // A start succeeded. If the daemon is down NOW it died later, which this
      // function knows nothing about — saying anything here would be invention.
      return null;
    case 'starting':
      // A daemon takes a moment to bind. Reporting "did not start" during that
      // window would accuse a start that is simply still in progress — so a fresh
      // marker means nothing yet.
      if (Date.now() - at.getTime() < STARTING_GRACE_MS) return null;
      // Issued but never reported back. TWO different things produce this, and the
      // wording must cover both: the child died at module load (its stack is in
      // daemon-startup.log), or no child was ever created — an exec failure on the
      // check path, which deliberately records nothing (see check.ts) and leaves
      // daemon-startup.log with no trace of this attempt at all. Claiming it
      // "exited during startup" would assert a death that may never have happened
      // and point at an empty file, so state only what is known and name both
      // places evidence can live.
      return {
        kind: 'did-not-start',
        detail: 'the daemon did not come up — see ~/.node9/daemon-startup.log and hook-debug.log',
        at,
        // `at` is the FIRST attempt of the streak, not the most recent one.
        label: 'start attempts failing since',
      };
    case 'failed':
      // A conclusive outcome overwrites, so here `at` really is the last attempt.
      return { kind: s.kind || 'failed', detail: s.detail || '', at, label: 'last start attempt' };
    default:
      return null; // unknown outcome from a newer version — say nothing
  }
}

/** Append one structured line: `[ISO] daemon-startup:<kind> <detail>`. Never throws. */
export function logDaemonStartup(kind: string, detail?: string): void {
  try {
    const file = DAEMON_STARTUP_LOG();
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    // NO capStartupLog() here. This is called by a daemon that has just written its
    // crash stack to stderr — which the spawner redirects into THIS file — so
    // truncating now would delete the stack milliseconds after it landed, leaving
    // the user with a one-line breadcrumb and the log that doctor points them at
    // empty. Capping belongs before the writes, which is what openStartupLogFd does.
    const line = `[${new Date().toISOString()}] daemon-startup:${kind}${detail ? ` ${detail}` : ''}\n`;
    fs.appendFileSync(file, line, 'utf-8');
  } catch {
    /* diagnostics are best-effort — never let logging break daemon startup/exit */
  }
}
