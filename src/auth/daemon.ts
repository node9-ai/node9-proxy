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
): Promise<string> {
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
    const { id } = (await res.json()) as { id: string };
    return id;
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
): Promise<string> {
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
  const { id } = (await res.json()) as { id: string };
  return id;
}

/** Clear a viewer-mode card from the daemon once Slack has decided. */
export async function resolveViaDaemon(
  id: string,
  decision: 'allow' | 'deny',
  internalToken: string
): Promise<void> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  await fetch(`${base}/resolve/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': internalToken },
    body: JSON.stringify({ decision }),
    signal: AbortSignal.timeout(3000),
  });
}
