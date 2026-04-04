// src/daemon/state.ts
// Shared mutable state, types, utility functions, and SSE/broadcast for the daemon.
// Imported by daemon/server.ts (routes) and daemon/index.ts (stopDaemon/daemonStatus).
import http from 'http';
import net from 'net';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import { RiskMetadata } from '../context-sniper';
import { DAEMON_PORT, DAEMON_HOST } from '../auth/daemon';
import { SuggestionTracker, type Suggestion } from './suggestion-tracker.js';
import { TaintStore } from './taint-store.js';
import { sessionCounters } from './session-counters.js';
import { sessionHistory } from './session-history.js';
export { sessionCounters, sessionHistory };
export type { HudStatus } from './session-counters.js';

export type { Suggestion };
export { TaintStore };

export { DAEMON_PORT, DAEMON_HOST };

// ── File paths ────────────────────────────────────────────────────────────────
const homeDir = os.homedir();
export const DAEMON_PID_FILE = path.join(homeDir, '.node9', 'daemon.pid');
export const DECISIONS_FILE = path.join(homeDir, '.node9', 'decisions.json');
export const AUDIT_LOG_FILE = path.join(homeDir, '.node9', 'audit.log');
export const TRUST_FILE = path.join(homeDir, '.node9', 'trust.json');
export const GLOBAL_CONFIG_FILE = path.join(homeDir, '.node9', 'config.json');
export const CREDENTIALS_FILE = path.join(homeDir, '.node9', 'credentials.json');
export const INSIGHT_COUNTS_FILE = path.join(homeDir, '.node9', 'insight-counts.json');

// ── Types ─────────────────────────────────────────────────────────────────────
export interface AuditEntry {
  ts: string;
  tool: string;
  args: unknown;
  decision: string;
  source: string;
}

export type Decision = 'allow' | 'deny' | 'abandoned';

export interface PendingEntry {
  id: string;
  toolName: string;
  args: unknown;
  riskMetadata?: RiskMetadata;
  /** Recovery command to display in the tail/browser recovery menu (e.g. "npm test"). */
  recoveryCommand?: string;
  /**
   * When true, the tail shows the card for context but does NOT enable keypress.
   * Used for recovery menu entries where the tty menu in check.ts is the sole decision maker.
   */
  viewOnly?: boolean;
  agent?: string;
  mcpServer?: string;
  timestamp: number;
  slackDelegated: boolean;
  timer: ReturnType<typeof setTimeout>;
  waiter: ((d: Decision, reason?: string) => void) | null;
  earlyDecision: Decision | null;
  earlyReason?: string;
  decisionSource?: string; // 'browser', 'terminal', or undefined (cloud/auto)
}

export interface SseClient {
  res: http.ServerResponse;
  capabilities: string[];
}

// ── Shared mutable state ──────────────────────────────────────────────────────
export const pending = new Map<string, PendingEntry>();
export const sseClients = new Set<SseClient>();
export const suggestionTracker = new SuggestionTracker(3);
export const suggestions = new Map<string, Suggestion>();
export const taintStore = new TaintStore();
/** Cumulative per-tool allow count for the 💡 insight line.
 *  Unlike suggestionTracker, this never resets after the suggestion threshold —
 *  only on deny. Used by all approval channels (terminal, browser, native popup).
 *  Persisted to disk so daemon restarts don't reset the nudge threshold.
 *
 *  Thread-safety: Node.js is single-threaded; all mutations happen in the
 *  main event loop so no locking is needed. If the daemon ever moves to
 *  worker_threads, this Map must be guarded (e.g. Atomics or message-passing). */
export const insightCounts = new Map<string, number>();

export function loadInsightCounts(): void {
  try {
    if (!fs.existsSync(INSIGHT_COUNTS_FILE)) return;
    const data = JSON.parse(fs.readFileSync(INSIGHT_COUNTS_FILE, 'utf-8')) as Record<
      string,
      number
    >;
    for (const [tool, count] of Object.entries(data)) {
      if (typeof count === 'number' && count > 0) insightCounts.set(tool, count);
    }
  } catch {}
}

export function saveInsightCounts(): void {
  try {
    const data: Record<string, number> = {};
    insightCounts.forEach((count, tool) => {
      data[tool] = count;
    });
    atomicWriteSync(INSIGHT_COUNTS_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
  } catch {}
}
let _abandonTimer: ReturnType<typeof setTimeout> | null = null;
export function getAbandonTimer() {
  return _abandonTimer;
}
export function setAbandonTimer(t: ReturnType<typeof setTimeout> | null) {
  _abandonTimer = t;
}

let _hadBrowserClient = false; // true once at least one SSE client has connected
export function getHadBrowserClient() {
  return _hadBrowserClient;
}
export function setHadBrowserClient(v: boolean) {
  _hadBrowserClient = v;
}

// setDaemonServer / getDaemonServer: avoids a circular dep between state.ts and
// server.ts — abandonPending() needs to call server.close() but server is created
// in server.ts. server.ts calls setDaemonServer() immediately after http.createServer().
let _daemonServer: http.Server | null = null;
export function setDaemonServer(s: http.Server): void {
  _daemonServer = s;
}
export function getDaemonServer(): http.Server | null {
  return _daemonServer;
}

// Module-level flag prevents double-registration if startDaemon() is called more
// than once (e.g. in tests). Boolean is race-safe unlike listenerCount checks.
export let daemonRejectionHandlerRegistered = false;
export function markRejectionHandlerRegistered(): void {
  daemonRejectionHandlerRegistered = true;
}

// ── Constants ─────────────────────────────────────────────────────────────────
export const AUTO_DENY_MS = 120_000;
export const TRUST_DURATIONS: Record<string, number> = {
  '30m': 30 * 60_000,
  '1h': 60 * 60_000,
  '2h': 2 * 60 * 60_000,
};

// True when the daemon was launched automatically by the hook/smart-runner.
export const autoStarted = process.env.NODE9_AUTO_STARTED === '1';

const ACTIVITY_SOCKET_PATH =
  process.platform === 'win32'
    ? '\\\\.\\pipe\\node9-activity'
    : path.join(os.tmpdir(), 'node9-activity.sock');

// ── Flight Recorder ring buffer — replayed to new SSE clients on connect ──────
export const ACTIVITY_RING_SIZE = 100;
export const activityRing: { event: string; data: unknown }[] = [];

// ── Utility functions ─────────────────────────────────────────────────────────

export function atomicWriteSync(
  filePath: string,
  data: string,
  options?: fs.WriteFileOptions
): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${filePath}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(tmpPath, data, options);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      /* best-effort: file may not have been created */
    }
    throw err;
  }
  try {
    fs.renameSync(tmpPath, filePath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      /* best-effort cleanup */
    }
    throw err;
  }
}

const SECRET_KEY_RE = /password|secret|token|key|apikey|credential|auth/i;

export function redactArgs(value: unknown): unknown {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(redactArgs);
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    result[k] = SECRET_KEY_RE.test(k) ? '[REDACTED]' : redactArgs(v);
  }
  return result;
}

export function appendAuditLog(data: { toolName: string; args: unknown; decision: string }): void {
  try {
    const entry: AuditEntry = {
      ts: new Date().toISOString(),
      tool: data.toolName,
      args: redactArgs(data.args),
      decision: data.decision,
      source: 'daemon',
    };
    const dir = path.dirname(AUDIT_LOG_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(AUDIT_LOG_FILE, JSON.stringify(entry) + '\n');
  } catch {}
}

export function getAuditHistory(limit = 20): AuditEntry[] {
  try {
    if (!fs.existsSync(AUDIT_LOG_FILE)) return [];
    const lines = fs.readFileSync(AUDIT_LOG_FILE, 'utf-8').trim().split('\n');
    if (lines.length === 1 && lines[0] === '') return [];
    return lines
      .slice(-limit)
      .map((l) => JSON.parse(l))
      .reverse();
  } catch {
    return [];
  }
}

export function getOrgName(): string | null {
  try {
    if (fs.existsSync(CREDENTIALS_FILE)) return 'Node9 Cloud';
  } catch {}
  return null;
}

export function hasStoredSlackKey(): boolean {
  return fs.existsSync(CREDENTIALS_FILE);
}

export function writeGlobalSetting(key: string, value: unknown): void {
  let config: Record<string, unknown> = {};
  try {
    if (fs.existsSync(GLOBAL_CONFIG_FILE)) {
      config = JSON.parse(fs.readFileSync(GLOBAL_CONFIG_FILE, 'utf-8')) as Record<string, unknown>;
    }
  } catch {}
  if (!config.settings || typeof config.settings !== 'object') config.settings = {};
  (config.settings as Record<string, unknown>)[key] = value;
  atomicWriteSync(GLOBAL_CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
}

export function writeTrustEntry(toolName: string, durationMs: number): void {
  try {
    interface TrustFile {
      entries: { tool: string; expiry: number }[];
    }
    let trust: TrustFile = { entries: [] };
    try {
      if (fs.existsSync(TRUST_FILE))
        trust = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8')) as TrustFile;
    } catch {}
    trust.entries = trust.entries.filter((e) => e.tool !== toolName && e.expiry > Date.now());
    trust.entries.push({ tool: toolName, expiry: Date.now() + durationMs });
    atomicWriteSync(TRUST_FILE, JSON.stringify(trust, null, 2));
  } catch {}
}

export function readPersistentDecisions(): Record<string, 'allow' | 'deny'> {
  try {
    if (fs.existsSync(DECISIONS_FILE)) {
      return JSON.parse(fs.readFileSync(DECISIONS_FILE, 'utf-8')) as Record<
        string,
        'allow' | 'deny'
      >;
    }
  } catch {}
  return {};
}

export function writePersistentDecision(toolName: string, decision: 'allow' | 'deny'): void {
  try {
    const decisions = readPersistentDecisions();
    decisions[toolName] = decision;
    atomicWriteSync(DECISIONS_FILE, JSON.stringify(decisions, null, 2));
    broadcast('decisions', decisions);
  } catch {}
}

export function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => resolve(body));
  });
}

export function openBrowser(url: string): void {
  if (process.env.NODE9_TESTING === '1') return;
  try {
    const args =
      process.platform === 'darwin'
        ? ['open', url]
        : process.platform === 'win32'
          ? ['cmd', '/c', 'start', '', url]
          : ['xdg-open', url];
    spawn(args[0], args.slice(1), { detached: true, stdio: 'ignore' }).unref();
  } catch {}
}

// ── SSE broadcast ─────────────────────────────────────────────────────────────

export function broadcast(event: string, data: unknown): void {
  // Buffer activity events so late-joining browsers get history
  if (event === 'activity') {
    activityRing.push({ event, data });
    if (activityRing.length > ACTIVITY_RING_SIZE) activityRing.shift();
  } else if (event === 'activity-result') {
    // Patch the status in the ring buffer so replayed history is up-to-date.
    // Intentional in-place mutation — safe because Node.js is single-threaded
    // and ring entries are only read during SSE replay on the same event loop tick.
    const { id, status, label } = data as { id: string; status: string; label?: string };
    for (let i = activityRing.length - 1; i >= 0; i--) {
      if ((activityRing[i].data as { id: string }).id === id) {
        Object.assign(activityRing[i].data as object, { status, label });
        break;
      }
    }
  }

  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach((client) => {
    try {
      client.res.write(msg);
    } catch {
      sseClients.delete(client);
    }
  });
}

export function hasInteractiveClient(): boolean {
  return [...sseClients].some((c) => c.capabilities.includes('input'));
}

export function abandonPending(): void {
  setAbandonTimer(null);
  pending.forEach((entry, id) => {
    clearTimeout(entry.timer);
    if (entry.waiter) entry.waiter('abandoned');
    else entry.earlyDecision = 'abandoned';
    pending.delete(id);
    broadcast('remove', { id });
  });

  if (autoStarted) {
    try {
      fs.unlinkSync(DAEMON_PID_FILE);
    } catch {}
    setTimeout(() => {
      getDaemonServer()?.close();
      process.exit(0);
    }, 200);
  }
}

// Write tools tracked for session history (stateful smart rules)
const WRITE_TOOL_NAMES = new Set([
  'write',
  'write_file',
  'create_file',
  'edit',
  'multiedit',
  'str_replace_based_edit_tool',
  'replace',
  'notebook_edit',
  'notebookedit',
]);

// ── Flight Recorder Unix socket ───────────────────────────────────────────────
// startActivitySocket is called by startDaemon() after the HTTP server is up.
export function startActivitySocket(): void {
  // Clean up stale socket file from previous run
  try {
    fs.unlinkSync(ACTIVITY_SOCKET_PATH);
  } catch {}

  const ACTIVITY_MAX_BYTES = 1024 * 1024; // 1 MB guard against runaway senders
  const unixServer = net.createServer((socket) => {
    const chunks: Buffer<ArrayBuffer>[] = [];
    let bytesReceived = 0;
    socket.on('data', (chunk: Buffer<ArrayBuffer>) => {
      bytesReceived += chunk.length;
      if (bytesReceived > ACTIVITY_MAX_BYTES) {
        socket.destroy();
        return;
      }
      chunks.push(chunk);
    });
    socket.on('end', () => {
      try {
        const data = JSON.parse(Buffer.concat(chunks).toString()) as {
          id: string;
          ts: number;
          tool: string;
          args?: unknown;
          status: string;
          label?: string;
          ruleHit?: string;
          observeWouldBlock?: boolean;
          hash?: string;
          argsSummary?: string;
          fileCount?: number;
        };
        // Track test results for stateful smart rules
        if (data.status === 'test_pass') {
          sessionHistory.recordTestPass(data.ts);
          return;
        }
        if (data.status === 'test_fail') {
          sessionHistory.recordTestFail(data.ts);
          return;
        }
        if (data.status === 'snapshot') {
          broadcast('snapshot', {
            hash: data.hash,
            tool: data.tool,
            argsSummary: data.argsSummary,
            fileCount: data.fileCount,
            ts: data.ts,
          });
          return;
        }

        if (data.status === 'pending') {
          broadcast('activity', {
            id: data.id,
            ts: data.ts,
            tool: data.tool,
            args: redactArgs(data.args),
            status: 'pending',
          });
        } else {
          // Update session counters for HUD
          if (data.status === 'allow') {
            sessionCounters.incrementAllowed();
            if (data.observeWouldBlock) sessionCounters.incrementWouldBlock();
            // Track file edits for stateful smart rules
            if (WRITE_TOOL_NAMES.has(data.tool.toLowerCase().replace(/[^a-z_]/g, '_'))) {
              sessionHistory.recordEdit(data.ts);
            }
          } else if (data.status === 'block') {
            sessionCounters.incrementBlocked();
            sessionCounters.recordBlockedTool(data.tool);
            if (data.ruleHit) sessionCounters.recordRuleHit(data.ruleHit);
          } else if (data.status === 'dlp') {
            sessionCounters.incrementBlocked();
            sessionCounters.incrementDlpHits();
            sessionCounters.recordBlockedTool(data.tool);
          } else if (data.status === 'taint') {
            sessionCounters.incrementBlocked();
            sessionCounters.recordBlockedTool(data.tool);
          }

          broadcast('activity-result', {
            id: data.id,
            status: data.status,
            label: data.label,
          });
        }
      } catch {}
    });
    socket.on('error', () => {});
  });

  unixServer.listen(ACTIVITY_SOCKET_PATH);
  process.on('exit', () => {
    try {
      fs.unlinkSync(ACTIVITY_SOCKET_PATH);
    } catch {}
  });
}
