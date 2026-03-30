// src/auth/daemon.ts
// Daemon interaction helpers: PID check, entry registration, long-polling, viewer cards.
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync } from 'child_process';
import { type RiskMetadata } from '../context-sniper';

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
    // PID file present — trust it: live PID → running, dead PID → not running
    try {
      const { pid, port } = JSON.parse(fs.readFileSync(pidFile, 'utf-8'));
      if (port !== DAEMON_PORT) return false;
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }

  // No PID file — port check catches orphaned daemons (PID file was lost)
  try {
    const r = spawnSync('ss', ['-Htnp', `sport = :${DAEMON_PORT}`], {
      encoding: 'utf8',
      timeout: 500,
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
  cwd?: string
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
): Promise<{ decision: 'allow' | 'deny' | 'abandoned'; source?: string }> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  const waitCtrl = new AbortController();
  const waitTimer = setTimeout(() => waitCtrl.abort(), 120_000);
  const onAbort = () => waitCtrl.abort();
  if (signal) signal.addEventListener('abort', onAbort);
  try {
    const waitRes = await fetch(`${base}/wait/${id}`, { signal: waitCtrl.signal });
    if (!waitRes.ok) return { decision: 'deny' };
    const { decision, source } = (await waitRes.json()) as { decision: string; source?: string };
    if (decision === 'allow') return { decision: 'allow', source };
    if (decision === 'abandoned') return { decision: 'abandoned', source };
    return { decision: 'deny', source };
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
