// src/tui/dashboard/data.ts
//
// Data plumbing for the dashboard spike. No React in this file — pure
// I/O + parsing helpers. Components import from here.
//
// Three sources:
//   1. SSE stream from the daemon (live activity)
//   2. ~/.node9/audit.log (historical aggregates within window)
//   3. runBlast() (current disk exposure)

import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import { runBlast } from '../../cli/commands/blast.js';
import { DAEMON_HOST, DAEMON_PORT, getInternalToken } from '../../auth/daemon.js';
import type { ActivityEvent, AuditAggregates, BlastSnapshot } from './types.js';

// ---------------------------------------------------------------------------
// Audit log parsing — minimal copy of the report.ts helper.
// We could refactor report.ts to export it but that's outside spike scope.
// ---------------------------------------------------------------------------

interface AuditEntry {
  ts: string;
  tool: string;
  args?: Record<string, unknown>;
  decision: string;
  checkedBy?: string;
  agent?: string;
  mcpServer?: string;
  source?: string;
  sessionId?: string;
}

function auditLogPath(): string {
  return path.join(os.homedir(), '.node9', 'audit.log');
}

export function readAuditEntries(): AuditEntry[] {
  const p = auditLogPath();
  if (!fs.existsSync(p)) return [];
  try {
    const lines = fs.readFileSync(p, 'utf8').split('\n');
    const out: AuditEntry[] = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line) as AuditEntry;
        if (e && typeof e.ts === 'string') out.push(e);
      } catch {
        // ignore malformed lines — same forgiving parse report.ts uses
      }
    }
    return out;
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Aggregation — given audit entries within window, produce the numbers
// each panel needs. Pure; safe to call on every window change.
// ---------------------------------------------------------------------------

const TEST_TOOLS = new Set(['Bash', 'bash']);

export function aggregateAudit(
  entries: AuditEntry[],
  startMs: number,
  endMs: number = Date.now()
): AuditAggregates {
  const inWindow = entries.filter((e) => {
    if (e.source === 'post-hook' || e.source === 'response-dlp') return false;
    const t = Date.parse(e.ts);
    return t >= startMs && t <= endMs;
  });

  let allow = 0;
  let block = 0;
  let review = 0;
  const sessionSet = new Set<string>();
  const mcpSet = new Set<string>();
  const toolMap = new Map<string, { calls: number; blocked: number }>();
  const blockMap = new Map<string, number>();
  const shellMap = new Map<string, number>();

  for (const e of inWindow) {
    if (e.sessionId) sessionSet.add(e.sessionId);
    if (e.mcpServer) mcpSet.add(e.mcpServer);

    const isAllow = e.decision === 'allow' || e.decision === 'observe-allow';
    const isReview = e.decision === 'review';
    if (isAllow) allow++;
    else if (isReview) review++;
    else block++;

    const t = toolMap.get(e.tool) ?? { calls: 0, blocked: 0 };
    t.calls++;
    if (!isAllow && !isReview) t.blocked++;
    toolMap.set(e.tool, t);

    if (!isAllow && e.checkedBy) {
      blockMap.set(e.checkedBy, (blockMap.get(e.checkedBy) ?? 0) + 1);
    }

    // Shell-cmd extraction: first token of args.command for Bash entries.
    if (TEST_TOOLS.has(e.tool) && typeof e.args?.command === 'string') {
      const head = (e.args.command as string).trim().split(/\s+/)[0];
      if (head && /^[a-zA-Z0-9._-]+$/.test(head)) {
        shellMap.set(head, (shellMap.get(head) ?? 0) + 1);
      }
    }
  }

  return {
    total: inWindow.length,
    allow,
    block,
    review,
    // Cost / tokens: not in audit.log itself; would need costSync data.
    // Spike returns 0 for both — add a banner in the UI rather than fake numbers.
    costUSD: 0,
    tokens: 0,
    sessions: sessionSet.size,
    mcpServers: mcpSet.size,
    mcpCalls: [...inWindow].filter((e) => !!e.mcpServer).length,
    byTool: [...toolMap.entries()]
      .sort((a, b) => b[1].calls - a[1].calls)
      .slice(0, 8)
      .map(([tool, v]) => ({ tool, calls: v.calls, blocked: v.blocked })),
    byBlock: [...blockMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([rule, count]) => ({ rule, count })),
    byShell: [...shellMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([cmd, count]) => ({ cmd, count })),
  };
}

// ---------------------------------------------------------------------------
// Blast — wraps runBlast() with privacy-friendly path truncation.
// ---------------------------------------------------------------------------

export function loadBlast(): BlastSnapshot {
  try {
    const r = runBlast();
    return {
      score: r.score,
      paths: r.reachable.slice(0, 5).map((f) => shortenPath(f.full)),
      envFindings: r.envFindings.length,
    };
  } catch {
    return { score: 100, paths: [], envFindings: 0 };
  }
}

function shortenPath(p: string): string {
  const home = os.homedir();
  return p.startsWith(home) ? p.replace(home, '~') : p;
}

// ---------------------------------------------------------------------------
// SSE subscription — connects to the daemon and yields ActivityEvent rows.
// Returns a teardown function the React effect cleans up.
// ---------------------------------------------------------------------------

interface SsePayload {
  id?: string;
  ts?: string;
  tool?: string;
  agent?: string;
  args?: Record<string, unknown>;
  decision?: string;
  reason?: string;
  checkedBy?: string;
  sessionId?: string;
  mcpServer?: string;
  // Activity events have these on the inner `activity` field on some events;
  // we union both shapes since the daemon broadcasts a few SSE event names.
  activity?: SsePayload;
}

export function subscribeToSse(
  onEvent: (e: ActivityEvent) => void,
  onError: (msg: string) => void
): () => void {
  const token = getInternalToken();
  if (!token) {
    onError('daemon not running (no ~/.node9/daemon.pid). Run: node9 daemon start');
    return () => {};
  }

  let req: http.ClientRequest | undefined;
  let aborted = false;

  const connect = () => {
    if (aborted) return;
    req = http.get(
      `http://${DAEMON_HOST}:${DAEMON_PORT}/events`,
      { headers: { 'X-Node9-Internal': token, Accept: 'text/event-stream' } },
      (res) => {
        if (res.statusCode !== 200) {
          onError(`daemon /events returned ${res.statusCode}`);
          return;
        }
        let buf = '';
        let currentEvent = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          buf += chunk;
          let idx: number;
          while ((idx = buf.indexOf('\n')) !== -1) {
            const line = buf.slice(0, idx).replace(/\r$/, '');
            buf = buf.slice(idx + 1);
            if (line.startsWith('event:')) {
              currentEvent = line.slice(6).trim();
            } else if (line.startsWith('data:')) {
              const raw = line.slice(5).trim();
              if (!raw) continue;
              try {
                const data = JSON.parse(raw) as SsePayload;
                const evt = toActivityEvent(currentEvent, data);
                if (evt) onEvent(evt);
              } catch {
                /* ignore malformed lines */
              }
            }
          }
        });
        res.on('end', () => {
          if (!aborted) onError('daemon disconnected; reconnecting…');
        });
      }
    );
    req.on('error', () => {
      if (!aborted) onError('daemon connection failed');
    });
  };

  connect();

  return () => {
    aborted = true;
    if (req) req.destroy();
  };
}

function toActivityEvent(eventName: string, data: SsePayload): ActivityEvent | null {
  // The daemon broadcasts several event types: `activity`, `activity-result`,
  // `add`, `remove`, `snapshot`, `execution-result`. The spike only renders
  // `activity` (incoming) and `add` (pending approval). Others are ignored.
  if (eventName !== 'activity' && eventName !== 'add' && eventName !== 'snapshot') return null;
  const payload = data.activity ?? data;
  if (!payload.tool || !payload.ts) return null;

  const verdict: ActivityEvent['verdict'] = (() => {
    const d = payload.decision;
    if (d === 'allow' || d === 'observe-allow') return 'allow';
    if (d === 'block') return 'block';
    if (d === 'review') return 'review';
    return 'pending';
  })();

  const command = payload.args?.command ?? payload.args?.file_path ?? payload.args?.path;
  const preview = (typeof command === 'string' ? command : JSON.stringify(payload.args ?? {}))
    .replace(/\s+/g, ' ')
    .slice(0, 70);

  return {
    id: payload.id ?? `${payload.ts}-${payload.tool}`,
    ts: payload.ts,
    tool: payload.tool,
    agent: payload.agent,
    preview,
    verdict,
    reason: payload.reason,
    checkedBy: payload.checkedBy,
    sessionId: payload.sessionId,
    mcpServer: payload.mcpServer,
  };
}
