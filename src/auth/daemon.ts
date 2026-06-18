// src/auth/daemon.ts
// Daemon interaction helpers: PID check, entry registration, long-polling, viewer cards.
import fs from 'fs';
import net from 'net';
import path from 'path';
import os from 'os';
import { type RiskMetadata } from '../context-sniper';

const ACTIVITY_SOCKET_PATH =
  process.platform === 'win32'
    ? '\\\\.\\pipe\\node9-activity'
    : path.join(os.tmpdir(), 'node9-activity.sock');

/**
 * Write a message to the activity Unix socket (flight recorder + session counters).
 * Returns true if the send succeeded, false if the daemon is not reachable.
 * Callers that set fromCLI=true on POST /check must check this return value —
 * if it's false, pass fromCLI=false so the daemon emits the activity event itself.
 */
export function notifyActivitySocket(data: Record<string, unknown>): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    try {
      const payload = JSON.stringify(data);
      const sock = net.createConnection(ACTIVITY_SOCKET_PATH);
      sock.on('connect', () => {
        sock.on('close', () => resolve(true));
        sock.end(payload);
      });
      sock.on('error', () => resolve(false));
    } catch {
      resolve(false);
    }
  });
}

/**
 * Query daemon state predicates for stateful smart rules.
 * Returns a map of predicate → boolean, or null if daemon unreachable.
 */
export async function checkStatePredicates(
  predicates: string[]
): Promise<Record<string, boolean> | null> {
  if (predicates.length === 0) return {};
  try {
    const qs = predicates.map(encodeURIComponent).join(',');
    const res = await fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/state/check?predicates=${qs}`, {
      signal: AbortSignal.timeout(100),
    });
    if (!res.ok) return null;
    return (await res.json()) as Record<string, boolean>;
  } catch {
    return null;
  }
}

export const DAEMON_PORT = 7391;
export const DAEMON_HOST = '127.0.0.1';

/**
 * Reads the internal token from the daemon PID file.
 * Used by notifyDaemonViewer / resolveViaDaemon so the Slack flow can
 * register and clear viewer-mode cards without needing the CSRF token.
 */
export function getInternalToken(): string | null {
  try {
    const pidFile = path.join(os.homedir(), '.node9', 'daemon.pid');
    if (!fs.existsSync(pidFile)) return null;
    const data = JSON.parse(fs.readFileSync(pidFile, 'utf-8')) as Record<string, unknown>;
    process.kill(data.pid as number, 0); // verify alive
    return (data.internalToken as string) ?? null;
  } catch {
    return null;
  }
}

export function isDaemonRunning(): boolean {
  const pidFile = path.join(os.homedir(), '.node9', 'daemon.pid');

  if (fs.existsSync(pidFile)) {
    let pid: unknown;
    let port: unknown;
    try {
      const data = JSON.parse(fs.readFileSync(pidFile, 'utf-8')) as Record<string, unknown>;
      pid = data.pid;
      port = data.port;
    } catch {
      // Unreadable or invalid JSON — treat as no daemon running.
      // Do NOT delete: the file may be mid-write by the daemon process.
      return false;
    }

    // Validate port before comparing — never trust file content blindly.
    if (port !== DAEMON_PORT) {
      // Wrong port — stale file from a config change.
      // Do NOT delete here: deleting based on attacker-controlled content creates
      // a TOCTOU attack where a malicious file causes us to remove the real PID file.
      // The daemon manages its own PID file; we only read it.
      return false;
    }

    // Validate pid strictly before passing to process.kill.
    // pid=0 signals the entire process group; pid=-1 signals all reachable processes.
    // Both are denial-of-service primitives available to any local user who can
    // write ~/.node9/daemon.pid. Reject anything outside the valid PID range.
    const MAX_PID = 4_194_304; // Linux kernel default max_pid (2^22)
    if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0 || pid > MAX_PID) {
      return false;
    }

    try {
      // Signal 0 is a pure existence probe — it sends no signal and cannot
      // affect the target process. The only outcomes are: success (process
      // exists and we have permission to signal it), ESRCH (no such process),
      // or EPERM (process exists but owned by a different uid). We never call
      // process.kill with any other signal number via this code path.
      process.kill(pid, 0);
    } catch (err: unknown) {
      // ESRCH = no such process (truly dead). Clean up the stale PID file only
      // in this case so the next call doesn't re-read it.
      // Do not clean up for EPERM (process exists but we can't signal it) —
      // that would remove a valid PID file for a daemon running as a different uid.
      if (
        err instanceof Error &&
        'code' in err &&
        (err as NodeJS.ErrnoException).code === 'ESRCH'
      ) {
        try {
          fs.unlinkSync(pidFile);
        } catch {
          /* non-fatal */
        }
      }
      return false;
    }

    // PID file present, JSON valid, port matches, PID validates, process exists.
    // We treat that as "running". A previous version also spawned `ss` to verify
    // the TCP port was bound — but `ss` is Linux-only (iproute2), causing this
    // function to always return false on macOS even when the daemon was up.
    // Callers that genuinely need HTTP-liveness (e.g. daemon-starter polling)
    // should use isDaemonReachable() instead.
    return true;
  }

  // No PID file — daemon not running. Detecting orphaned daemons (process up,
  // PID file lost) requires a port probe; that probe is portable only via
  // spawning `lsof`/`ss`, which we deliberately avoid here to keep this hot
  // path sync, fast, and cross-platform. The orphan case is recovered at
  // daemon startup via the EADDRINUSE handler in src/daemon/server.ts.
  return false;
}

/**
 * Async HTTP-liveness probe. Use this when a caller genuinely needs to know
 * the daemon's HTTP server is accepting requests right now (e.g. after
 * spawning the daemon, before issuing the first /check call). isDaemonRunning()
 * is the cheap sync check — sufficient for most call sites.
 */
export async function isDaemonReachable(timeoutMs = 500): Promise<boolean> {
  try {
    const res = await fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/settings`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Register a new approval entry with the daemon and return its ID.
 * Both the browser racer (GET /wait) and the terminal racer (POST /decision)
 * share this entry — it must be created before the race starts.
 */
export async function registerDaemonEntry(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string },
  riskMetadata?: RiskMetadata,
  activityId?: string,
  cwd?: string,
  recoveryCommand?: string,
  /** When true, the daemon skips background authorizeHeadless and holds the entry
   *  open until the caller resolves it via resolveViaDaemon. Use for recovery menu
   *  entries where check.ts is the sole decision maker via the tty menu. */
  skipBackgroundAuth?: boolean,
  /** When true, the tail shows the card for context only (no interactive keypress). */
  viewOnly?: boolean,
  /** When true, the daemon skips cloud's immediate-allow for the background auth pass.
   *  Set when a local smart rule with verdict "review" matched in the hook process. */
  localSmartRuleMatched?: boolean,
  /** When false, the socket send of the activity event failed — daemon must emit it. */
  socketActivitySent?: boolean
): Promise<{ id: string; allowCount: number }> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const res = await fetch(`${base}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolName,
        args,
        agent: meta?.agent,
        mcpServer: meta?.mcpServer,
        // fromCLI=true tells the daemon the CLI already sent the activity event via
        // socket. If the socket send failed (socketActivitySent=false), set fromCLI=false
        // so the daemon emits the activity event itself — tail never misses an entry.
        fromCLI: socketActivitySent !== false,
        // Pass the flight-recorder ID so the daemon uses the same UUID for
        // activity-result as the CLI used for the pending activity event.
        activityId,
        ...(riskMetadata && { riskMetadata }),
        ...(cwd && { cwd }),
        ...(recoveryCommand && { recoveryCommand }),
        ...(skipBackgroundAuth && { skipBackgroundAuth: true }),
        ...(viewOnly && { viewOnly: true }),
        ...(localSmartRuleMatched && { localSmartRuleMatched: true }),
      }),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error('Daemon fail');
    const { id, allowCount } = (await res.json()) as { id: string; allowCount?: number };
    return { id, allowCount: allowCount ?? 1 };
  } finally {
    clearTimeout(timer);
  }
}

/** Long-poll the daemon for a decision on an already-registered entry. */
export async function waitForDaemonDecision(
  id: string,
  signal?: AbortSignal
): Promise<{ decision: 'allow' | 'deny' | 'abandoned'; source?: string; reason?: string }> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  const waitCtrl = new AbortController();
  const waitTimer = setTimeout(() => waitCtrl.abort(), 120_000);
  const onAbort = () => waitCtrl.abort();
  if (signal) signal.addEventListener('abort', onAbort);
  try {
    const waitRes = await fetch(`${base}/wait/${id}`, { signal: waitCtrl.signal });
    if (!waitRes.ok) return { decision: 'deny' };
    const { decision, source, reason } = (await waitRes.json()) as {
      decision: string;
      source?: string;
      reason?: string;
    };
    if (decision === 'allow') return { decision: 'allow', source };
    if (decision === 'abandoned') return { decision: 'abandoned', source };
    return { decision: 'deny', source, reason };
  } finally {
    clearTimeout(waitTimer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

/** Register a viewer-mode card on the daemon (Slack is the real authority).
 *
 *  Mirrors registerDaemonEntry's fromCLI/activityId contract: when the CLI
 *  has already sent the 'activity' event via the Unix socket, we tell the
 *  daemon to skip its own 'activity' broadcast and reuse the same id.
 *  Without this, the cloud-enforced path produced TWO 'activity' SSE
 *  events per logical command — one from state.ts:688 (socket handler)
 *  and one from server.ts:274 (/check handler with fromCLI=false). */
export async function notifyDaemonViewer(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string },
  riskMetadata?: RiskMetadata,
  activityId?: string,
  /** When false, the socket send of the activity event failed — daemon must emit it. */
  socketActivitySent?: boolean
): Promise<{ id: string; allowCount: number }> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  const res = await fetch(`${base}/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      toolName,
      args,
      slackDelegated: true,
      agent: meta?.agent,
      mcpServer: meta?.mcpServer,
      ...(riskMetadata && { riskMetadata }),
      // fromCLI=true tells the daemon the CLI already sent the activity
      // event via socket. Same contract as registerDaemonEntry — without
      // it the daemon double-emits 'activity' for cloud-enforced flows.
      fromCLI: socketActivitySent !== false,
      activityId,
    }),
    signal: AbortSignal.timeout(3000),
  });
  if (!res.ok) throw new Error('Daemon unreachable');
  const { id, allowCount } = (await res.json()) as { id: string; allowCount?: number };
  return { id, allowCount: allowCount ?? 1 };
}

/**
 * Notify the daemon to taint a file path after a DLP write-block.
 * Must be awaited before the hook process exits — fire-and-forget loses the
 * taint because the process exits before the fetch completes.
 */
export async function notifyTaint(filePath: string, source: string): Promise<void> {
  if (!isDaemonRunning()) return;
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  try {
    await fetch(`${base}/taint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: filePath, source }),
      signal: AbortSignal.timeout(1000),
    });
  } catch {
    // Taint is best-effort — daemon unreachable is non-fatal
  }
}

/**
 * Notify the daemon to propagate taint from src to dest (cp/mv semantics).
 * clearSource=true implements mv: the source taint is removed after propagation.
 */
export async function notifyTaintPropagate(
  src: string,
  dest: string,
  clearSource = false
): Promise<void> {
  if (!isDaemonRunning()) return;
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  try {
    await fetch(`${base}/taint/propagate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ src, dest, clearSource }),
      signal: AbortSignal.timeout(1000),
    });
  } catch {
    // Propagation is best-effort — daemon unreachable is non-fatal
  }
}

// Re-export TaintRecord so callers share one canonical type instead of an inline duplicate.
export type { TaintRecord } from '../daemon/taint-store.js';
import type { TaintRecord, SessionTaintRecord } from '../daemon/taint-store.js';

export interface SessionTaintCheckResult {
  tainted: boolean;
  record?: SessionTaintRecord;
  /** True when the daemon was unreachable — caller treats as untainted (fail-open). */
  daemonUnavailable?: boolean;
}

export interface TaintCheckResult {
  tainted: boolean;
  record?: TaintRecord;
  /**
   * True when the taint daemon was unreachable and the check could not be
   * completed. The caller should treat this as a soft warning: files may be
   * tainted but the status is unknown. Distinct from tainted:false, which
   * means the daemon was reachable and confirmed the paths are clean.
   */
  daemonUnavailable?: boolean;
}

/**
 * Ask the daemon if any of the given file paths are tainted.
 * Returns the first tainted record found, or { tainted: false }.
 *
 * Fail-open: returns { tainted: false } on network error so a daemon blip
 * doesn't stall the agent. The error is logged to hook-debug.log so it's
 * visible without being fatal.
 */
export async function checkTaint(paths: string[]): Promise<TaintCheckResult> {
  if (paths.length === 0) return { tainted: false };
  if (!isDaemonRunning()) return { tainted: false, daemonUnavailable: true };
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  try {
    const res = await fetch(`${base}/taint/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paths }),
      signal: AbortSignal.timeout(2000),
    });
    return (await res.json()) as TaintCheckResult;
  } catch (err) {
    // Fail-open: a taint check failure must not block the agent entirely.
    // Log so the operator can diagnose daemon instability without user impact.
    try {
      const { appendToLog, HOOK_DEBUG_LOG } = await import('../audit/index.js');
      appendToLog(HOOK_DEBUG_LOG, {
        ts: new Date().toISOString(),
        event: 'checkTaint-error',
        error: String(err),
        paths,
      });
    } catch {
      /* audit write failure is non-fatal */
    }
    return { tainted: false, daemonUnavailable: true };
  }
}

/**
 * Taint a session after its tool output was flagged (gap1). Best-effort, must be
 * awaited before the PostToolUse hook exits (same reason as notifyTaint).
 */
export async function notifySessionTaint(sessionId: string, source: string): Promise<void> {
  if (!sessionId || !isDaemonRunning()) return;
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  try {
    await fetch(`${base}/session-taint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, source }),
      signal: AbortSignal.timeout(1000),
    });
  } catch {
    // Session taint is best-effort — daemon unreachable is non-fatal.
  }
}

/**
 * Ask the daemon whether a session is tainted (gap1). Fail-open: a daemon blip
 * returns { tainted: false } so it never stalls the agent — same contract as
 * checkTaint.
 */
export async function checkSessionTaint(sessionId: string): Promise<SessionTaintCheckResult> {
  if (!sessionId || !isDaemonRunning()) return { tainted: false };
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  try {
    const res = await fetch(`${base}/session-taint/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId }),
      signal: AbortSignal.timeout(2000),
    });
    return (await res.json()) as SessionTaintCheckResult;
  } catch {
    // Fail-open: a session-taint check failure must not block the agent.
    return { tainted: false, daemonUnavailable: true };
  }
}

/**
 * List currently tainted sessions (gap1). Taint lives in daemon memory, so a
 * stopped daemon means there are no active taints — returns []. For `node9
 * session-taint list` / the clear command's prefix resolution.
 */
export async function listSessionTaints(): Promise<SessionTaintRecord[]> {
  if (!isDaemonRunning()) return [];
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  try {
    const res = await fetch(`${base}/session-taint/list`, { signal: AbortSignal.timeout(2000) });
    const json = (await res.json()) as { records?: SessionTaintRecord[] };
    return json.records ?? [];
  } catch {
    return [];
  }
}

/**
 * Clear a session taint (or all). For `node9 session-taint clear` — lets a user
 * who has resolved a flagged output release the session so its next high-risk
 * action isn't held for review. daemonUnavailable distinguishes "no daemon"
 * (nothing to clear) from "cleared 0" (daemon up, id wasn't tainted).
 */
export async function clearSessionTaint(opts: {
  sessionId?: string;
  all?: boolean;
}): Promise<{ ok: boolean; cleared: number; daemonUnavailable?: boolean }> {
  if (!isDaemonRunning()) return { ok: false, cleared: 0, daemonUnavailable: true };
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  try {
    const res = await fetch(`${base}/session-taint/clear`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opts),
      signal: AbortSignal.timeout(2000),
    });
    return (await res.json()) as { ok: boolean; cleared: number };
  } catch {
    return { ok: false, cleared: 0, daemonUnavailable: true };
  }
}

/** Clear a viewer-mode card from the daemon once Slack has decided.
 *  Also used by the Event Bridge to notify the daemon when native popup or
 *  cloud wins the race — so SuggestionTracker sees every human decision. */
export async function resolveViaDaemon(
  id: string,
  decision: 'allow' | 'deny',
  internalToken: string,
  source?: string
): Promise<void> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  await fetch(`${base}/resolve/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': internalToken },
    body: JSON.stringify({ decision, ...(source && { source }) }),
    signal: AbortSignal.timeout(3000),
  });
}
