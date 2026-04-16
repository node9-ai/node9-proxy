// src/auth/daemon.ts
// Daemon interaction helpers: PID check, entry registration, long-polling, viewer cards.
import fs from 'fs';
import net from 'net';
import path from 'path';
import os from 'os';
import { spawnSync } from 'child_process';
import { type RiskMetadata } from '../context-sniper';

const ACTIVITY_SOCKET_PATH =
  process.platform === 'win32'
    ? '\\\\.\\pipe\\node9-activity'
    : path.join(os.tmpdir(), 'node9-activity.sock');

/**
 * Write a message to the activity Unix socket (flight recorder + session counters).
 * Resolves immediately if the daemon is not running.
 */
export function notifyActivitySocket(data: Record<string, unknown>): Promise<void> {
  return new Promise<void>((resolve) => {
    try {
      const payload = JSON.stringify(data);
      const sock = net.createConnection(ACTIVITY_SOCKET_PATH);
      sock.on('connect', () => {
        sock.on('close', resolve);
        sock.end(payload);
      });
      sock.on('error', resolve);
    } catch {
      resolve();
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
      // Verify the process is alive
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

    // Verify the TCP port is actually accepting connections.
    // process.kill(pid,0) only confirms the process exists — it could still
    // be in early startup before server.listen() completes, or the PID could
    // be reused by an unrelated process. A TCP probe is the authoritative check.
    const r = spawnSync('ss', ['-Htnp', `sport = :${DAEMON_PORT}`], {
      encoding: 'utf8',
      timeout: 300,
    });
    if (r.status === 0 && (r.stdout ?? '').includes(`:${DAEMON_PORT}`)) return true;
    // PID alive but port not open yet (daemon starting) or PID reuse by another
    // process. Don't clean the PID file — daemon may still be initializing.
    return false;
  }

  // No PID file — port check catches orphaned daemons (PID file was lost)
  try {
    const r = spawnSync('ss', ['-Htnp', `sport = :${DAEMON_PORT}`], {
      encoding: 'utf8',
      timeout: 300,
    });
    return r.status === 0 && (r.stdout ?? '').includes(`:${DAEMON_PORT}`);
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
  localSmartRuleMatched?: boolean
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
        fromCLI: true,
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

/** Register a viewer-mode card on the daemon (Slack is the real authority). */
export async function notifyDaemonViewer(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string },
  riskMetadata?: RiskMetadata
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
import type { TaintRecord } from '../daemon/taint-store.js';

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
