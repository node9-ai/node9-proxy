// src/daemon/state.ts
// Shared mutable state, types, utility functions, and SSE/broadcast for the daemon.
// Imported by daemon/server.ts (routes) and daemon/index.ts (stopDaemon/daemonStatus).
import http from 'http';
import net from 'net';
import fs from 'fs';
import path from 'path';
import os from 'os';
// `spawn` import removed — only consumer was openBrowser() (deleted).
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
  /** New fields for MCP discovery */
  type?: 'tool-call' | 'mcp-discovery';
  mcpTools?: Array<{ name: string; description?: string }>;
  serverKey?: string;
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

// ── Large MCP response ring — replayed to new SSE clients on connect ──────────
export interface LargeResponseEvent {
  ts: string;
  toolName: string;
  serverKey: string;
  originalBytes: number;
}
export const LARGE_RESPONSE_RING_SIZE = 20;
export const largeResponseRing: LargeResponseEvent[] = [];

// ── Cached scan result — pushed by CLI `node9 scan`, served to browser ────────
export let cachedScanResult: unknown = null;
export let cachedScanTs = 0;
export const SCAN_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export function setCachedScanResult(result: unknown): void {
  cachedScanResult = result;
  cachedScanTs = Date.now();
}

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

export function writeTrustEntry(
  toolName: string,
  durationMs: number,
  commandPattern?: string
): void {
  try {
    interface TrustFile {
      entries: { tool: string; commandPattern?: string; expiry: number }[];
    }
    let trust: TrustFile = { entries: [] };
    try {
      if (fs.existsSync(TRUST_FILE))
        trust = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8')) as TrustFile;
    } catch {}
    trust.entries = trust.entries.filter(
      (e) => !(e.tool === toolName && e.commandPattern === commandPattern) && e.expiry > Date.now()
    );
    trust.entries.push({
      tool: toolName,
      ...(commandPattern && { commandPattern }),
      expiry: Date.now() + durationMs,
    });
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
    // broadcast('decisions') removed — only the browser dashboard
    // consumed it. The new `node9 decisions list` CLI re-reads the
    // file on demand; no live update channel needed.
  } catch {}
}

export function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => resolve(body));
  });
}

// openBrowser() helper removed — local browser dashboard retired (v3).

// ── FinOps: cost estimation ───────────────────────────────────────────────────
// Passive mode only — estimates cost from tool args at allow time.
// Read tools: file size → input tokens ($3/1M for Sonnet default).
// Write/edit tools: content length → output tokens ($15/1M for Sonnet default).
// Bash output cost is not estimable at PreToolUse time — omitted.

const INPUT_PRICE_PER_1M = 3.0; // $/1M input tokens  (claude-sonnet-4-6)
const OUTPUT_PRICE_PER_1M = 15.0; // $/1M output tokens (claude-sonnet-4-6)
const BYTES_PER_TOKEN = 4;

function estimateToolCost(tool: string, args: unknown): number | undefined {
  const a = (args ?? {}) as Record<string, unknown>;
  const t = tool.toLowerCase().replace(/[^a-z_]/g, '_');

  // Read: file content will be returned to the AI as input tokens
  if (t.includes('read') || t === 'glob' || t === 'grep') {
    const filePath = (a.file_path ?? a.path) as string | undefined;
    if (filePath) {
      try {
        const bytes = fs.statSync(filePath).size;
        return (bytes / BYTES_PER_TOKEN / 1_000_000) * INPUT_PRICE_PER_1M;
      } catch {
        /* file not found or inaccessible — skip */
      }
    }
  }

  // Write: AI generated this content = output tokens
  if (t.includes('write')) {
    const content = (a.content ?? '') as string;
    return (String(content).length / BYTES_PER_TOKEN / 1_000_000) * OUTPUT_PRICE_PER_1M;
  }

  // Edit (str_replace): new_string is AI-generated output
  if (t.includes('edit') || t === 'str_replace_based_edit_tool') {
    const newStr = (a.new_string ?? '') as string;
    return (String(newStr).length / BYTES_PER_TOKEN / 1_000_000) * OUTPUT_PRICE_PER_1M;
  }

  // Bash/shell: the command text itself is AI-generated output tokens
  if (t === 'bash' || t === 'shell' || t === 'run_shell_command' || t === 'terminal_execute') {
    const command = String(a.command ?? a.cmd ?? a.input ?? '');
    if (command.length > 0) {
      return (command.length / BYTES_PER_TOKEN / 1_000_000) * OUTPUT_PRICE_PER_1M;
    }
  }

  return undefined;
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
    const { id, status, label, costEstimate } = data as {
      id: string;
      status: string;
      label?: string;
      costEstimate?: number;
    };
    for (let i = activityRing.length - 1; i >= 0; i--) {
      if ((activityRing[i].data as { id: string }).id === id) {
        Object.assign(activityRing[i].data as object, { status, label, costEstimate });
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
// The activity socket can disappear at runtime (systemd-tmpfiles cleanup,
// manual rm, tmp on tmpfs after suspend). When that happens every hook's
// notifyActivitySocket() silently returns false and `node9 tail` shows
// nothing live until the user runs `node9 daemon restart`. A 2s polling
// probe rebinds automatically; the circuit breaker stops infinite rebind
// loops if something keeps deleting the socket.
//
// Why polling (setInterval) and not fs.watch (inotify): an earlier version
// used fs.watch for "near-instant" recovery, but inotify fires for the
// daemon's own unlink-then-listen sequence inside bindActivitySocket().
// The watcher's callback would observe the file gone (between unlink and
// listen completing) and trigger another rebind, which fired another
// inotify event, etc. — a self-reinforcing loop that quickly tripped the
// circuit breaker. setInterval is structurally incapable of self-triggering
// (a tick can't fire in response to its own actions), so the loop is gone.
// Trade-off: detection latency goes from ~instant to ≤2s, which is fine.
export const ACTIVITY_REBIND_MAX_ATTEMPTS = 5;
export const ACTIVITY_REBIND_WINDOW_MS = 60_000;
const ACTIVITY_HEALTH_PROBE_MS = 2_000;

let activitySocketServer: net.Server | null = null;
let activityHealthInterval: NodeJS.Timeout | null = null;
let activityRebindAttempts: number[] = [];
let activityCircuitTripped = false;

function logActivitySocket(msg: string): void {
  // Always-on diagnostics — flight-recorder failures are invisible without this.
  try {
    fs.appendFileSync(
      path.join(homeDir, '.node9', 'hook-debug.log'),
      `[${new Date().toISOString()}] [activity-socket] ${msg}\n`
    );
  } catch {}
}

/** Returns true if a rebind is allowed; false if the circuit breaker has tripped. */
function shouldRebind(now: number = Date.now()): boolean {
  if (activityCircuitTripped) return false;
  activityRebindAttempts = activityRebindAttempts.filter(
    (t) => now - t < ACTIVITY_REBIND_WINDOW_MS
  );
  activityRebindAttempts.push(now);
  if (activityRebindAttempts.length > ACTIVITY_REBIND_MAX_ATTEMPTS) {
    activityCircuitTripped = true;
    return false;
  }
  return true;
}

// Test-only hooks. Not intended for production callers.
export const __activitySocketTestHooks = {
  shouldRebind,
  isCircuitTripped: () => activityCircuitTripped,
  resetCircuitBreaker: () => {
    activityRebindAttempts = [];
    activityCircuitTripped = false;
  },
};

// startActivitySocket is called by startDaemon() after the HTTP server is up.
export function startActivitySocket(): void {
  bindActivitySocket();

  // Polling probe — checks every ACTIVITY_HEALTH_PROBE_MS whether the socket
  // file is still present. setInterval cannot self-trigger from its own
  // bind/unlink work the way fs.watch did, so no rebind loops.
  activityHealthInterval = setInterval(() => {
    if (!fs.existsSync(ACTIVITY_SOCKET_PATH)) attemptRebind('health-probe');
  }, ACTIVITY_HEALTH_PROBE_MS);
  activityHealthInterval.unref();

  process.on('exit', () => {
    if (activityHealthInterval) clearInterval(activityHealthInterval);
    try {
      fs.unlinkSync(ACTIVITY_SOCKET_PATH);
    } catch {}
  });
}

function attemptRebind(reason: string): void {
  if (!shouldRebind()) {
    logActivitySocket(
      `circuit breaker tripped after ${ACTIVITY_REBIND_MAX_ATTEMPTS} attempts in ${ACTIVITY_REBIND_WINDOW_MS}ms — flight recorder down`
    );
    broadcast('flight-recorder-down', {
      reason: 'rebind-loop',
      message: 'Activity socket repeatedly disappearing — run: node9 daemon restart',
    });
    return;
  }
  logActivitySocket(`rebinding (reason: ${reason}, attempt ${activityRebindAttempts.length})`);
  if (activitySocketServer) {
    try {
      activitySocketServer.close();
    } catch {}
    activitySocketServer = null;
  }
  bindActivitySocket();
}

function bindActivitySocket(): void {
  // Clean up stale socket file from previous run / failed bind
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
          agent?: string;
          mcpServer?: string;
          sessionId?: string;
          durationMs?: number;
          isError?: boolean;
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

        if (data.status === 'execution-completed') {
          // Emitted by the MCP gateway when an upstream tool call response
          // arrives. Distinct from 'activity-result' (which marks the auth
          // decision) — this marks the actual upstream completion plus
          // wall-clock duration.
          broadcast('execution-result', {
            id: data.id,
            ts: data.ts,
            tool: data.tool,
            agent: data.agent,
            mcpServer: data.mcpServer,
            durationMs: data.durationMs,
            isError: data.isError,
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
            agent: data.agent,
            mcpServer: data.mcpServer,
            sessionId: data.sessionId,
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

          const costEstimate =
            data.status === 'allow' ? estimateToolCost(data.tool, data.args) : undefined;
          if (costEstimate != null && costEstimate > 0) sessionCounters.addCost(costEstimate);

          broadcast('activity-result', {
            id: data.id,
            status: data.status,
            label: data.label,
            costEstimate,
            agent: data.agent,
            mcpServer: data.mcpServer,
            sessionId: data.sessionId,
          });
        }
      } catch {}
    });
    socket.on('error', () => {});
  });

  // Layer 1 — listen() failures used to be silent. Now they hit hook-debug.log
  // so operators can diagnose flight-recorder outages without strace.
  unixServer.on('error', (err: Error) => {
    logActivitySocket(`server error: ${err.message}`);
  });

  unixServer.listen(ACTIVITY_SOCKET_PATH, () => {
    logActivitySocket(`bound to ${ACTIVITY_SOCKET_PATH}`);
  });
  activitySocketServer = unixServer;
}
