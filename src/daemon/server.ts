// src/daemon/server.ts
// HTTP server for the Node9 localhost approval daemon.
// All route handlers live here; shared state is in daemon/state.ts.
import http from 'http';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { randomUUID } from 'crypto';
import { spawnSync } from 'child_process';
import chalk from 'chalk';
import { authorizeHeadless, getGlobalSettings, getConfig, _resetConfigCache } from '../core';
// SHIELDS / readActiveShields no longer used in server.ts after the
// /shields route was removed (v3 browser-removal). CLI shield commands
// import these directly.
// UI_HTML_TEMPLATE import removed — local browser dashboard retired (v3).
import {
  scanClaudeHistory,
  scanGeminiHistory,
  scanCodexHistory,
  type ScanResult,
} from '../cli/commands/scan';
import { buildScanSummary } from '../scan-summary';
import {
  DAEMON_PORT,
  DAEMON_HOST,
  DAEMON_PID_FILE,
  AUTO_DENY_MS,
  TRUST_DURATIONS,
  autoStarted,
  activityRing,
  pending,
  sseClients,
  setDaemonServer,
  getAbandonTimer,
  setAbandonTimer,
  getHadBrowserClient,
  setHadBrowserClient,
  daemonRejectionHandlerRegistered,
  markRejectionHandlerRegistered,
  atomicWriteSync,
  redactArgs,
  appendAuditLog,
  getAuditHistory,
  getOrgName,
  writeGlobalSetting,
  writeTrustEntry,
  writePersistentDecision,
  readBody,
  broadcast,
  abandonPending,
  startActivitySocket,
  type PendingEntry,
  type SseClient,
  type Decision,
  taintStore,
  sessionTaintStore,
  insightCounts,
  loadInsightCounts,
  saveInsightCounts,
  sessionCounters,
  sessionHistory,
  type HudStatus,
  largeResponseRing,
  LARGE_RESPONSE_RING_SIZE,
  type LargeResponseEvent,
  cachedScanResult,
  cachedScanTs,
  SCAN_CACHE_TTL_MS,
} from './state';
import { extractCommandPattern } from '../auth/state.js';
import { startCostSync } from '../costSync.js';
import { startCloudSync, startForensicBroadcast } from './sync.js';
import { startAuditShipper } from './audit-shipper.js';
import { classifyDecision } from '../audit/decision.js';
import { startDlpScanner } from './dlp-scanner.js';
import { startMcpReconciler } from './mcp-reconciler.js';
import { startHookHeal } from './hook-heal.js';
import { logDaemonStartup, recordStartupState } from './startup-log.js';
import { readMcpToolsConfig, updateServerDiscovery, approveServer } from './mcp-tools.js';

export type DaemonReportPeriod = 'today' | '7d' | '30d' | 'month';

export interface DaemonReportBody {
  summary: { total: number; allowed: number; blocked: number; dlp: number; loops: number };
  daily: Array<{ date: string; calls: number; blocked: number }>;
  topTools: Array<{ name: string; value: number }>;
  topBlockedTools: Array<{ name: string; value: number }>;
  byAgent: Array<{ agent: string; total: number; blocked: number; dlp: number }>;
}

/**
 * Aggregate GET /report from raw audit rows.
 *
 * Extracted from the route handler so the one invariant that matters here can
 * be tested: EVERY blocked count in the response comes from the same mapper.
 * When this lived inline, `summary.blocked` was converged onto
 * `classifyDecision` while `topBlockedTools` and `byAgent.blocked` kept their
 * own `startsWith('allow')` rule twelve lines below — so a single response
 * disagreed with itself by 950 rows on a real log, and there was no seam to
 * write a test against.
 */
export function buildDaemonReport(
  allEntries: Array<Record<string, unknown>>,
  period: DaemonReportPeriod,
  now: Date
): DaemonReportBody {
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  let start = new Date(todayStart);
  if (period === '7d') start.setDate(start.getDate() - 6);
  else if (period === '30d') start.setDate(start.getDate() - 29);
  else if (period === 'month') start = new Date(now.getFullYear(), now.getMonth(), 1);

  const entries = allEntries.filter((e) => {
    if (e.source === 'post-hook' || e.source === 'response-dlp') return false;
    return new Date(e.ts as string) >= start;
  });

  // THE rule for this endpoint. Every blocked count below calls this and
  // nothing else — that is the whole point of the extraction.
  const isBlocked = (e: Record<string, unknown>) => classifyDecision(e).outcome === 'deny';
  const checkedBy = (e: Record<string, unknown>) =>
    typeof e.checkedBy === 'string' ? e.checkedBy : undefined;

  const summary = {
    total: entries.length,
    // The inline `startsWith('allow')` this replaces counted every non-allow
    // row as "blocked" — so DLP findings, MCP-discovery events and, worst, all
    // the observe-mode "would have blocked" rows inflated the blocked count
    // with things that were never refusals.
    allowed: entries.filter((e) => classifyDecision(e).outcome === 'allow').length,
    blocked: entries.filter(isBlocked).length,
    dlp: entries.filter((e) => checkedBy(e)?.includes('dlp')).length,
    loops: entries.filter((e) => checkedBy(e) === 'loop-detected').length,
  };

  // For "today" we group by hour (00-23) so the chart has real shape.
  // Other periods group by calendar day.
  const dailyMap = new Map<string, { date: string; calls: number; blocked: number }>();
  if (period === 'today') {
    // Pre-populate 24 hour buckets so the chart always shows a full day
    for (let h = 0; h < 24; h++) {
      const key = String(h).padStart(2, '0') + ':00';
      dailyMap.set(key, { date: key, calls: 0, blocked: 0 });
    }
    for (const e of entries) {
      const hour = new Date(e.ts as string).getHours();
      const key = String(hour).padStart(2, '0') + ':00';
      const d = dailyMap.get(key)!;
      d.calls++;
      if (isBlocked(e)) d.blocked++;
    }
  } else {
    for (const e of entries) {
      const date = (e.ts as string).slice(0, 10);
      const d = dailyMap.get(date) || { date, calls: 0, blocked: 0 };
      d.calls++;
      if (isBlocked(e)) d.blocked++;
      dailyMap.set(date, d);
    }
  }

  const topToolsMap = new Map<string, number>();
  const topBlockedMap = new Map<string, number>();
  for (const e of entries) {
    const tool = String(e.tool ?? '');
    topToolsMap.set(tool, (topToolsMap.get(tool) || 0) + 1);
    if (isBlocked(e)) topBlockedMap.set(tool, (topBlockedMap.get(tool) || 0) + 1);
  }
  const top5 = (m: Map<string, number>) =>
    [...m.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, value]) => ({ name, value }));

  const agentMap = new Map<
    string,
    { agent: string; total: number; blocked: number; dlp: number }
  >();
  for (const e of entries) {
    const key = (e.agent as string) || 'unknown';
    const a = agentMap.get(key) ?? { agent: key, total: 0, blocked: 0, dlp: 0 };
    a.total++;
    if (isBlocked(e)) a.blocked++;
    if (checkedBy(e)?.includes('dlp')) a.dlp++;
    agentMap.set(key, a);
  }

  return {
    summary,
    daily: [...dailyMap.values()].sort((a, b) => a.date.localeCompare(b.date)),
    topTools: top5(topToolsMap),
    topBlockedTools: top5(topBlockedMap),
    byAgent: [...agentMap.values()].sort((a, b) => b.total - a.total),
  };
}

export function startDaemon(): void {
  // A4c: a synchronous throw in these inits used to exit the process silently
  // (stdio:'ignore' on the auto-start path). Record it so a startup death is
  // diagnosable. NOTE: this does NOT catch a module-LOAD crash (e.g. ERR_REQUIRE_ESM)
  // — that throws at import time, before this runs; A4b (child stderr → the same log)
  // is what captures those.
  try {
    startCostSync();
    startCloudSync();
    startForensicBroadcast();
    startAuditShipper();
    startDlpScanner();
    startMcpReconciler();
    startHookHeal();
    loadInsightCounts(); // restore persisted nudge counters across restarts
  } catch (err) {
    // Preserve the FULL stack: to stderr (captured by the auto-start path's fd
    // redirect → daemon-startup.log, and shown for a foreground `node9 daemon`),
    // and a one-line breadcrumb to the structured log.
    const stack = err instanceof Error ? (err.stack ?? err.message) : String(err);
    console.error('\n🛑 Node9 daemon startup failed:\n' + stack);
    logDaemonStartup('startup-throw', err instanceof Error ? err.message : String(err));
    recordStartupState('failed', 'startup-throw', err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
  // Single per-process token. Stored in ~/.node9/daemon.pid (mode 0600)
  // and read by every local CLI client (`node9 tail`, mcp-gateway,
  // orchestrator) via auth/daemon.ts:getInternalToken.
  //
  // Two header names accepted for back-compat:
  //   - 'x-node9-internal'  — preferred, used by all current consumers
  //   - 'x-node9-token'     — older CSRF-style header from when the
  //                           browser dashboard issued a separate token.
  //                           Browser is gone (v3 sprint); the alias is
  //                           kept so any in-flight client requests
  //                           landing across the upgrade still work.
  const internalToken = randomUUID();
  const validToken = (req: http.IncomingMessage) =>
    req.headers['x-node9-internal'] === internalToken ||
    req.headers['x-node9-token'] === internalToken;

  // ── Graceful Idle Timeout ────────────────────────────────────────────────
  const IDLE_TIMEOUT_MS = 12 * 60 * 60 * 1000; // 12 hours
  const watchMode = process.env.NODE9_WATCH_MODE === '1';
  let idleTimer: NodeJS.Timeout | undefined;
  function resetIdleTimer() {
    if (watchMode) return; // Watch mode — never idle-timeout
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      if (autoStarted) {
        try {
          fs.unlinkSync(DAEMON_PID_FILE);
        } catch {}
      }
      process.exit(0);
    }, IDLE_TIMEOUT_MS);
    idleTimer.unref(); // Don't hold the process open just for the timer
  }
  resetIdleTimer(); // Start the clock

  // Allowed Host header values — DNS rebinding guard.
  // A malicious website that DNS-rebinds attacker.com → 127.0.0.1 would send
  // Host: attacker.com, which won't match. Only 127.0.0.1 and localhost are valid.
  const allowedHosts = new Set([`127.0.0.1:${DAEMON_PORT}`, `localhost:${DAEMON_PORT}`]);

  const server = http.createServer(async (req, res) => {
    const host = req.headers.host ?? '';
    if (!allowedHosts.has(host)) {
      res.writeHead(421, { 'Content-Type': 'text/plain' });
      return res.end('Misdirected Request');
    }

    const reqUrl = new URL(req.url || '/', `http://${host}`);
    const { pathname } = reqUrl;

    // GET / (HTML browser dashboard) — removed in v3 browser-removal sprint.
    // The local HTTP server now exists only for: SSE stream consumed by
    // node9 tail, /decision/* approval writes, and /check from the proxy
    // hook. No HTML surface.

    if (req.method === 'GET' && pathname === '/events') {
      // SSE stream — gated on the per-process token. Closes the
      // pre-v3-sprint hole where any local process could subscribe
      // and harvest pending tool-call args. CLI clients read the
      // token from the PID file via getInternalToken() and pass it
      // as the X-Node9-Internal header.
      if (!validToken(req)) {
        return res.writeHead(403).end();
      }
      const capParam = reqUrl.searchParams.get('capabilities') ?? '';
      const capabilities = capParam
        ? capParam
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean)
        : [];

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      const at = getAbandonTimer();
      if (at) {
        clearTimeout(at);
        setAbandonTimer(null);
      }
      setHadBrowserClient(true);
      const sseClient: SseClient = { res, capabilities };
      sseClients.add(sseClient);
      res.write(
        `event: init\ndata: ${JSON.stringify({
          requests: Array.from(pending.values()).map((e) => ({
            id: e.id,
            toolName: e.toolName,
            args: e.args,
            riskMetadata: e.riskMetadata,
            ...(e.recoveryCommand && { recoveryCommand: e.recoveryCommand }),
            ...(e.viewOnly && { viewOnly: true }),
            slackDelegated: e.slackDelegated,
            timestamp: e.timestamp,
            agent: e.agent,
            mcpServer: e.mcpServer,
            allowCount: (insightCounts.get(e.toolName) ?? 0) + 1,
          })),
          orgName: getOrgName(),
          autoDenyMs: getConfig().settings.approvalTimeoutMs ?? AUTO_DENY_MS,
        })}\n\n`
      );
      // event: decisions / shields-status / csrf removed in v3 sprint.
      // Pre-v3, the daemon emitted the CSRF token on every SSE connect
      // so any subscriber could harvest it and forge /decision posts.
      // Now: clients read the per-process token from ~/.node9/daemon.pid
      // (mode 0600) directly, and they had to send it just to subscribe
      // here — no need to re-broadcast.
      // Replay large-response history so late-joining browsers see past events
      if (largeResponseRing.length > 0) {
        res.write(
          `event: mcp-large-response-history\ndata: ${JSON.stringify({ events: largeResponseRing })}\n\n`
        );
      }
      // Replay recent activity history so late-joining browsers see the feed
      for (const item of activityRing) {
        res.write(`event: ${item.event}\ndata: ${JSON.stringify(item.data)}\n\n`);
      }
      return req.on('close', () => {
        sseClients.delete(sseClient);
        if (sseClients.size === 0 && pending.size > 0) {
          // Give 10s if browser was already open (page reload / brief disconnect),
          // 15s on cold-start (browser needs time to open and connect SSE).
          setAbandonTimer(setTimeout(abandonPending, getHadBrowserClient() ? 10_000 : 15_000));
        }
      });
    }

    if (req.method === 'POST' && pathname === '/check') {
      try {
        resetIdleTimer(); // Agent is active, reset the shutdown clock
        _resetConfigCache(); // Always read fresh config — catches login/manual edits without restart

        const body = await readBody(req);
        if (body.length > 65_536) return res.writeHead(413).end();
        const {
          toolName,
          args,
          slackDelegated = false,
          agent,
          mcpServer,
          riskMetadata,
          recoveryCommand,
          skipBackgroundAuth = false,
          viewOnly = false,
          fromCLI = false,
          activityId,
          cwd,
          localSmartRuleMatched = false,
        } = JSON.parse(body);
        // When fromCLI is true the CLI already sent an 'activity' event with
        // activityId via the Unix socket. Reuse that ID so the daemon's
        // 'activity-result' broadcast matches what tail.ts has in its pending map.
        const id = (fromCLI && typeof activityId === 'string' && activityId) || randomUUID();
        const entry: PendingEntry = {
          id,
          toolName,
          args,
          riskMetadata: riskMetadata ?? undefined,
          ...(typeof recoveryCommand === 'string' && recoveryCommand && { recoveryCommand }),
          ...(viewOnly && { viewOnly: true }),
          agent: typeof agent === 'string' ? agent : undefined,
          mcpServer: typeof mcpServer === 'string' ? mcpServer : undefined,
          slackDelegated: !!slackDelegated,
          timestamp: Date.now(),
          earlyDecision: null,
          waiter: null,
          timer: setTimeout(() => {
            if (pending.has(id)) {
              const e = pending.get(id)!;
              appendAuditLog({
                toolName: e.toolName,
                args: e.args,
                decision: 'auto-deny',
              });
              if (e.waiter) e.waiter('deny', 'No response — auto-denied after timeout');
              else {
                e.earlyDecision = 'deny';
                e.earlyReason = 'No response — auto-denied after timeout';
              }
              pending.delete(id);
              broadcast('remove', { id, decision: 'deny' });
            }
          }, getConfig().settings.approvalTimeoutMs ?? AUTO_DENY_MS),
        };
        pending.set(id, entry);

        // Flight recorder: CLI callers already sent 'activity' via the Unix socket
        // (notifyActivity), so skip it here to avoid duplicate entries. External
        // callers (non-CLI integrations) set fromCLI=false and need the broadcast.
        if (!fromCLI) {
          broadcast('activity', {
            id,
            ts: entry.timestamp,
            tool: toolName,
            args: redactArgs(args),
            status: 'pending',
            agent: entry.agent,
            mcpServer: entry.mcpServer,
          });
        }

        const projectCwd = typeof cwd === 'string' && path.isAbsolute(cwd) ? cwd : undefined;
        const projectConfig = getConfig(projectCwd);
        const browserEnabled = projectConfig.settings.approvers?.browser !== false;
        const terminalEnabled = projectConfig.settings.approvers?.terminal !== false;
        // Broadcast 'add' when the browser dashboard is on OR terminal approver is
        // enabled. Tail may connect after the event fires and will see pending entries
        // via the SSE stream's initial state — don't gate on hasInteractiveClient().
        if (browserEnabled || terminalEnabled) {
          broadcast('add', {
            id,
            toolName,
            args,
            riskMetadata: entry.riskMetadata,
            ...(entry.recoveryCommand && { recoveryCommand: entry.recoveryCommand }),
            ...(entry.viewOnly && { viewOnly: true }),
            slackDelegated: entry.slackDelegated,
            agent: entry.agent,
            mcpServer: entry.mcpServer,
            interactive: terminalEnabled,
            // allowCount = what this count will be if the user allows.
            // Terminal uses this to show the 💡 insight line on the Nth consecutive approval.
            allowCount: (insightCounts.get(toolName) ?? 0) + 1,
          });
          // Browser auto-open removed: approvals route through terminal popup
          // and native popup; the local browser UI is opt-in via
          // `node9 daemon start --openui`. Users who want the browser
          // dashboard can open localhost:7391 manually.
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id, allowCount: (insightCounts.get(toolName) ?? 0) + 1 }));

        // Run the full policy + cloud + native pipeline in the background.
        // Browser and terminal racers are skipped (no TTY, browser card already exists via SSE).
        // Skip when slackDelegated: the hook process already owns the cloud race for this
        // request — running a second initNode9SaaS here would create a duplicate pending
        // cloud request that never gets resolved.
        // Skip when skipBackgroundAuth: check.ts owns the recovery menu decision and will
        // resolve the entry via /resolve/ after the tty menu completes.
        if (slackDelegated || skipBackgroundAuth) return;
        authorizeHeadless(
          toolName,
          args,
          {
            agent: typeof agent === 'string' ? agent : undefined,
            mcpServer: typeof mcpServer === 'string' ? mcpServer : undefined,
          },
          { calledFromDaemon: true, localSmartRuleMatched: !!localSmartRuleMatched }
        )
          .then((result) => {
            const e = pending.get(id);
            if (!e) return; // Already resolved (browser click or auto-deny timer)

            // If no background channels were available (no cloud, no native),
            // leave the entry alive so the browser dashboard can decide.
            if (result.noApprovalMechanism) return;

            // In audit mode the hook auto-approves without blocking the tool.
            // The daemon entry is for display only — leave it for browser/tail
            // to resolve interactively (or for the auto-deny timer).
            if (result.checkedBy === 'audit') return;

            // First write wins — POST /decision (browser or tail) may have already
            // resolved this entry while authorizeHeadless was running in the background.
            if (e.earlyDecision !== null) return;

            // ── Flight Recorder: update the feed item with the final verdict ──
            broadcast('activity-result', {
              id,
              status: result.approved
                ? 'allow'
                : result.blockedByLabel?.includes('DLP')
                  ? 'dlp'
                  : 'block',
              label: result.blockedByLabel,
              agent: e.agent,
              mcpServer: e.mcpServer,
            });

            clearTimeout(e.timer);
            const decision: Decision = result.approved ? 'allow' : 'deny';
            appendAuditLog({ toolName: e.toolName, args: e.args, decision });
            if (e.waiter) {
              e.waiter(decision, result.reason);
              pending.delete(id);
              broadcast('remove', { id, decision });
            } else {
              e.earlyDecision = decision;
              e.earlyReason = result.reason;
            }
          })
          .catch((err) => {
            const e = pending.get(id);
            if (!e) return;
            clearTimeout(e.timer);
            const reason =
              (err as { reason?: string })?.reason || 'No response — request timed out';
            if (e.waiter) e.waiter('deny', reason);
            else {
              e.earlyDecision = 'deny';
              e.earlyReason = reason;
            }
            pending.delete(id);
            broadcast('remove', { id, decision: 'deny' });
          });

        return;
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'GET' && pathname.startsWith('/wait/')) {
      const id = pathname.split('/').pop()!;
      const entry = pending.get(id);
      if (!entry) return res.writeHead(404).end();
      if (entry.earlyDecision) {
        clearTimeout(entry.timer);
        const source = entry.decisionSource;
        pending.delete(id);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        const body: { decision: Decision; reason?: string; source?: string } = {
          decision: entry.earlyDecision,
        };
        if (entry.earlyReason) body.reason = entry.earlyReason;
        if (source) body.source = source;
        return res.end(JSON.stringify(body));
      }
      entry.waiter = (d, reason?) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        const body: { decision: Decision; reason?: string; source?: string } = { decision: d };
        if (reason) body.reason = reason;
        if (entry.decisionSource) body.source = entry.decisionSource;
        res.end(JSON.stringify(body));
      };
      // When the CLI aborts the long-poll (e.g. native popup won the race),
      // clean up the entry and dismiss the tail card.
      // Delay 200ms so the Event Bridge POST /resolve/ (fired in finish() just
      // after abort()) arrives first and carries the real decision.
      // If /resolve/ arrives first it deletes the entry — the timeout is a no-op.
      req.on('close', () => {
        setTimeout(() => {
          const e = pending.get(id);
          if (e && e.waiter && e.earlyDecision === null) {
            clearTimeout(e.timer);
            pending.delete(id);
            broadcast('remove', { id }); // no decision — preserves tail count
          }
        }, 200);
      });
      return;
    }

    if (req.method === 'POST' && pathname.startsWith('/decision/')) {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const id = pathname.split('/').pop()!;
        const entry = pending.get(id);
        if (!entry) return res.writeHead(404).end();
        // Idempotency: first write wins.
        if (entry.earlyDecision !== null) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ conflict: true, decision: entry.earlyDecision }));
        }
        const { decision, persist, trustDuration, reason, source } = JSON.parse(
          await readBody(req)
        ) as {
          decision: string;
          persist?: boolean;
          trustDuration?: string;
          reason?: string;
          source?: string;
        };

        // Trust session
        if (decision === 'trust' && trustDuration) {
          const ms = TRUST_DURATIONS[trustDuration] ?? 60 * 60_000;
          const commandPattern = extractCommandPattern(entry.toolName, entry.args);
          writeTrustEntry(entry.toolName, ms, commandPattern);
          appendAuditLog({
            toolName: entry.toolName,
            args: entry.args,
            decision: `trust:${trustDuration}`,
          });
          clearTimeout(entry.timer);
          if (entry.waiter) {
            entry.waiter('allow');
            pending.delete(id);
            broadcast('remove', { id, decision: 'allow' });
          } else {
            entry.earlyDecision = 'allow';
            broadcast('remove', { id, decision: 'allow' });
            entry.timer = setTimeout(() => pending.delete(id), 30_000);
          }
          res.writeHead(200);
          return res.end(JSON.stringify({ ok: true }));
        }

        const resolvedDecision = decision === 'allow' || decision === 'deny' ? decision : 'deny';
        if (persist) writePersistentDecision(entry.toolName, resolvedDecision);
        appendAuditLog({
          toolName: entry.toolName,
          args: entry.args,
          decision: resolvedDecision,
        });
        clearTimeout(entry.timer);

        // ── Smart Rule Suggestions ────────────────────────────────────────────
        // Track human allow decisions. The browser dashboard's
        // suggestion-card surface is gone (v3 sprint), so the
        // suggestion tracker no longer fires. insightCounts still
        // drives the 💡 hint in `node9 tail` after N consecutive allows.
        if (resolvedDecision === 'allow' && !persist) {
          insightCounts.set(entry.toolName, (insightCounts.get(entry.toolName) ?? 0) + 1);
          saveInsightCounts();
        } else if (resolvedDecision === 'deny') {
          insightCounts.delete(entry.toolName);
          saveInsightCounts();
        }

        // source is validated against an allowlist AFTER appendAuditLog so the
        // raw user-supplied value never reaches any log string — no log injection.
        const VALID_SOURCES = new Set(['terminal', 'browser', 'native', 'terminal-redirect']);
        if (source && VALID_SOURCES.has(source)) entry.decisionSource = source;
        if (entry.waiter) {
          entry.waiter(resolvedDecision, reason);
          pending.delete(id!);
          broadcast('remove', { id, decision: resolvedDecision });
        } else {
          entry.earlyDecision = resolvedDecision;
          entry.earlyReason = reason;
          broadcast('remove', { id, decision: resolvedDecision });
          entry.timer = setTimeout(() => pending.delete(id!), 30_000);
        }
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'GET' && pathname === '/settings') {
      try {
        const s = getGlobalSettings();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ...s, autoStarted }));
      } catch (err) {
        console.error(chalk.red('[node9 daemon] GET /settings failed:'), err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'internal' }));
      }
    }

    if (req.method === 'GET' && pathname === '/status') {
      try {
        const s = getGlobalSettings();
        const counters = sessionCounters.get();
        const mode = (s.mode ?? 'standard') as HudStatus['mode'];
        const status: HudStatus = {
          mode,
          session: {
            allowed: counters.allowed,
            blocked: counters.blocked,
            dlpHits: counters.dlpHits,
            wouldBlock: counters.wouldBlock,
            estimatedCost: counters.estimatedCost,
          },
          taintedCount: taintStore.list().length,
          lastRuleHit: counters.lastRuleHit,
          lastBlockedTool: counters.lastBlockedTool,
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(status));
      } catch (err) {
        console.error(chalk.red('[node9 daemon] GET /status failed:'), err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'internal' }));
      }
    }

    if (req.method === 'GET' && pathname === '/state/check') {
      const predicatesParam = reqUrl.searchParams.get('predicates') ?? '';
      const predicates = predicatesParam.split(',').filter(Boolean);
      const results: Record<string, boolean> = {};
      for (const p of predicates) {
        results[p] = sessionHistory.checkPredicate(p);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(results));
    }

    if (req.method === 'POST' && pathname === '/settings') {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const body = await readBody(req);
        const data = JSON.parse(body);
        if (data.autoStartDaemon !== undefined)
          writeGlobalSetting('autoStartDaemon', data.autoStartDaemon);
        if (data.slackEnabled !== undefined) writeGlobalSetting('slackEnabled', data.slackEnabled);
        if (data.enableTrustSessions !== undefined)
          writeGlobalSetting('enableTrustSessions', data.enableTrustSessions);
        if (data.enableUndo !== undefined) writeGlobalSetting('enableUndo', data.enableUndo);
        if (data.enableHookLogDebug !== undefined)
          writeGlobalSetting('enableHookLogDebug', data.enableHookLogDebug);
        if (data.approvers !== undefined) writeGlobalSetting('approvers', data.approvers);
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    // GET /slack-status, POST /slack-key, DELETE /decisions/<toolName>
    // — all removed in v3 browser-removal sprint. Slack-local approvals
    // are dropped (SaaS handles Slack); persistent-decision management
    // moves to the new `node9 decisions list / clear` CLI in step 7.

    if (req.method === 'POST' && pathname.startsWith('/resolve/')) {
      const internalAuth = req.headers['x-node9-internal'];
      if (internalAuth !== internalToken) return res.writeHead(403).end();
      try {
        const id = pathname.split('/').pop()!;
        const entry = pending.get(id);
        if (!entry) return res.writeHead(404).end();
        const { decision, source } = JSON.parse(await readBody(req)) as {
          decision: string;
          source?: string;
        };
        const resolvedResolveDecision: Decision = decision === 'allow' ? 'allow' : 'deny';
        appendAuditLog({
          toolName: entry.toolName,
          args: entry.args,
          decision: resolvedResolveDecision,
        });
        clearTimeout(entry.timer);

        // insightCounts tracks all human approvals so the 💡 insight
        // line appears consistently across all approval channels (tail).
        // The Smart Rule Suggestions surface (browser-only) was removed
        // in v3 sprint; suggestionTracker is no longer driven from here.
        if (resolvedResolveDecision === 'allow') {
          insightCounts.set(entry.toolName, (insightCounts.get(entry.toolName) ?? 0) + 1);
          saveInsightCounts();
        } else {
          insightCounts.delete(entry.toolName);
          saveInsightCounts();
        }

        const VALID_RESOLVE_SOURCES = new Set(['terminal', 'browser', 'native']);
        if (source && VALID_RESOLVE_SOURCES.has(source)) entry.decisionSource = source;

        if (entry.waiter) entry.waiter(resolvedResolveDecision);
        else entry.earlyDecision = resolvedResolveDecision;
        pending.delete(id);
        broadcast('remove', { id, decision: resolvedResolveDecision });
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'POST' && pathname === '/events/clear') {
      activityRing.length = 0;
      sessionCounters.reset();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true }));
    }

    if (req.method === 'GET' && pathname === '/audit') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(getAuditHistory()));
    }

    // GET /shields removed (browser-only read). Shield management moves
    // to CLI: `node9 shield list` / `node9 shield enable <name>` /
    // `node9 shield disable <name>` (already exist).

    if (req.method === 'GET' && pathname === '/report') {
      if (!validToken(req)) return res.writeHead(403).end();
      const periodParam = reqUrl.searchParams.get('period') || '7d';
      const period = (['today', '7d', '30d', 'month'] as const).includes(periodParam as any)
        ? (periodParam as 'today' | '7d' | '30d' | 'month')
        : '7d';

      const logPath = path.join(os.homedir(), '.node9', 'audit.log');
      if (!fs.existsSync(logPath)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(
          JSON.stringify({
            summary: { total: 0, allowed: 0, blocked: 0, dlp: 0, loops: 0 },
            daily: [],
            topTools: [],
            topBlockedTools: [],
            byAgent: [],
          })
        );
      }

      try {
        const raw = fs.readFileSync(logPath, 'utf-8');
        const allEntries = raw.split('\n').flatMap((line) => {
          if (!line.trim()) return [];
          try {
            return [JSON.parse(line)];
          } catch {
            return [];
          }
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(buildDaemonReport(allEntries, period, new Date())));
      } catch {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Failed to parse report' }));
      }
    }

    // POST /scan/push removed — was used to push scan results to the
    // browser dashboard. CLI scan output is now the only surface.
    // GET /scan stays — used by the daemon's HUD / status endpoints.

    if (req.method === 'GET' && pathname === '/scan') {
      if (!validToken(req)) return res.writeHead(403).end();

      // Return pushed scan result if it's fresh (avoids re-scanning after `node9 scan`)
      if (cachedScanResult !== null && Date.now() - cachedScanTs < SCAN_CACHE_TTL_MS) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(cachedScanResult));
      }

      try {
        const d = new Date();
        d.setDate(d.getDate() - 30);
        d.setHours(0, 0, 0, 0);

        const EMPTY_SCAN: ScanResult = {
          filesScanned: 0,
          sessions: 0,
          totalToolCalls: 0,
          bashCalls: 0,
          findings: [],
          dlpFindings: [],
          loopFindings: [],
          totalCostUSD: 0,
          firstDate: null,
          lastDate: null,
          sessionsWithEarlySecrets: 0,
        };
        let claude: ScanResult = EMPTY_SCAN;
        let gemini: ScanResult = EMPTY_SCAN;
        let codex: ScanResult = EMPTY_SCAN;

        try {
          claude = scanClaudeHistory(d);
        } catch (e) {
          console.error('Claude scan failed:', e);
        }
        try {
          gemini = scanGeminiHistory(d);
        } catch (e) {
          console.error('Gemini scan failed:', e);
        }
        try {
          codex = scanCodexHistory(d);
        } catch (e) {
          console.error('Codex scan failed:', e);
        }

        const summary = buildScanSummary([
          { id: 'claude', label: 'Claude', icon: '🤖', scan: claude },
          { id: 'gemini', label: 'Gemini', icon: '♊', scan: gemini },
          { id: 'codex', label: 'Codex', icon: '🔮', scan: codex },
        ]);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ status: 'complete', summary }));
      } catch (err) {
        console.error('Scan failed:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'History scan failed' }));
      }
    }

    // POST /shields removed — shield toggling moves to CLI
    // (`node9 shield enable/disable`) which writes the same shields.json.

    // ── Suggestions routes — removed (browser-only) ──────────────────────────

    // GET /suggestions, POST /suggestions/<id>/apply, POST /suggestions/<id>/dismiss
    // — all removed in v3 browser-removal sprint. The suggestion engine
    // (smart-rule recommendations after N consecutive allows) had its
    // user-facing surface only in the browser dashboard. Tracker is kept
    // in memory but no longer surfaced; step 3 will drop the tracker if
    // it has no other consumer.

    // ── Taint — record a tainted file path ───────────────────────────────────
    // Called by the hook process after a DLP write-block to persist the taint
    // in the long-running daemon so later tool calls can check it.
    // No CSRF token required — callers are local hook subprocesses, not browsers.
    if (req.method === 'POST' && pathname === '/taint') {
      try {
        const body = JSON.parse(await readBody(req)) as {
          path?: unknown;
          source?: unknown;
          ttlMs?: unknown;
          fromEid?: unknown;
        };
        if (typeof body.path !== 'string' || typeof body.source !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'path and source are required strings' }));
        }
        const ttlMs = typeof body.ttlMs === 'number' ? body.ttlMs : undefined;
        // Phase D2 — store the edge source; /taint/check returns the whole
        // record, so fromEid rides back to the block site automatically.
        const fromEid = typeof body.fromEid === 'string' ? body.fromEid : undefined;
        taintStore.taint(body.path, body.source, ttlMs, fromEid);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    // ── Taint check — query whether any paths are tainted ────────────────────
    // Called by the hook process before approving a network/upload operation.
    if (req.method === 'POST' && pathname === '/taint/check') {
      try {
        const body = JSON.parse(await readBody(req)) as { paths?: unknown };
        if (!Array.isArray(body.paths)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'paths must be an array' }));
        }
        // Reject upfront if any element is not a string — silently skipping
        // non-strings would allow a mixed array to sneak through the check.
        if ((body.paths as unknown[]).some((p) => typeof p !== 'string')) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'all paths must be strings' }));
        }
        for (const p of body.paths as string[]) {
          const record = taintStore.check(p);
          if (record) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ tainted: true, record }));
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ tainted: false }));
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    // ── Taint propagate — copy/move taint from source to destination path ────
    // Called by the hook process after a file copy (cp) or move (mv) involving
    // a tainted source. clearSource=true implements mv semantics.
    if (req.method === 'POST' && pathname === '/taint/propagate') {
      try {
        const body = JSON.parse(await readBody(req)) as {
          src?: unknown;
          dest?: unknown;
          clearSource?: unknown;
        };
        if (typeof body.src !== 'string' || typeof body.dest !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'src and dest are required strings' }));
        }
        const clearSource = body.clearSource === true;
        taintStore.propagate(body.src, body.dest, clearSource);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    // ── Session taint (gap1) — flag a session that consumed poisoned tool
    // output, so its next high-risk call is routed to review. Set by the
    // PostToolUse `log` hook; queried by the next PreToolUse `check`.
    if (req.method === 'POST' && pathname === '/session-taint') {
      try {
        const body = JSON.parse(await readBody(req)) as {
          sessionId?: unknown;
          source?: unknown;
          ttlMs?: unknown;
        };
        if (typeof body.sessionId !== 'string' || typeof body.source !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'sessionId and source are required strings' }));
        }
        const ttlMs = typeof body.ttlMs === 'number' ? body.ttlMs : undefined;
        sessionTaintStore.taint(body.sessionId, body.source, ttlMs);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    if (req.method === 'POST' && pathname === '/session-taint/check') {
      try {
        const body = JSON.parse(await readBody(req)) as { sessionId?: unknown };
        if (typeof body.sessionId !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'sessionId must be a string' }));
        }
        const record = sessionTaintStore.check(body.sessionId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(record ? { tainted: true, record } : { tainted: false }));
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    if (req.method === 'GET' && pathname === '/session-taint/list') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ records: sessionTaintStore.list() }));
    }

    if (req.method === 'POST' && pathname === '/session-taint/clear') {
      try {
        const body = JSON.parse(await readBody(req)) as { sessionId?: unknown; all?: unknown };
        if (body.all === true) {
          const cleared = sessionTaintStore.list().length;
          sessionTaintStore.clear();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: true, cleared }));
        }
        if (typeof body.sessionId !== 'string' || body.sessionId.length === 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(
            JSON.stringify({ error: 'sessionId (non-empty) or all:true is required' })
          );
        }
        const cleared = sessionTaintStore.clearSession(body.sessionId) ? 1 : 0;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true, cleared }));
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    // ── MCP Tools — list and configure disabled tools ────────────────────────
    if (req.method === 'GET' && pathname === '/mcp/tools') {
      if (!validToken(req)) return res.writeHead(403).end();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(readMcpToolsConfig()));
    }

    if (req.method === 'POST' && pathname === '/mcp/tools') {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const { serverKey, disabledTools } = JSON.parse(await readBody(req));
        if (
          typeof serverKey !== 'string' ||
          serverKey.length < 1 ||
          serverKey.length > 256 ||
          !/^[\w.-]+$/.test(serverKey) ||
          !Array.isArray(disabledTools)
        ) {
          res.writeHead(400).end();
          return;
        }
        approveServer(serverKey, disabledTools);
        appendAuditLog({
          toolName: `mcp-server:${serverKey}`,
          args: { disabledTools },
          decision: 'allow',
        });
        // broadcast('mcp-tools-updated') removed — browser-only listener.
        // The route itself + the mcp-tool-gating flow goes in step 6.
        res.writeHead(200).end();
        return;
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    if (req.method === 'POST' && pathname === '/mcp/discovered') {
      // Called by gateway, requires internal token
      if (req.headers['x-node9-internal'] !== internalToken) return res.writeHead(403).end();
      try {
        const { serverKey, tools, name } = JSON.parse(await readBody(req));
        if (
          typeof serverKey !== 'string' ||
          serverKey.length < 1 ||
          serverKey.length > 256 ||
          !/^[\w.-]+$/.test(serverKey) ||
          !Array.isArray(tools)
        ) {
          res.writeHead(400).end();
          return;
        }

        const safeName = typeof name === 'string' && name ? name.slice(0, 80) : undefined;
        const status = updateServerDiscovery(serverKey, tools, safeName);
        if (status === 'new' || status === 'drift') {
          appendAuditLog({
            toolName: `mcp-server:${serverKey}`,
            args: { toolCount: tools.length, status },
            decision: 'mcp-discovered',
          });
          // Trigger interactive approval flow
          const id = randomUUID();
          const entry: PendingEntry = {
            id,
            type: 'mcp-discovery',
            serverKey,
            mcpTools: tools,
            toolName: 'mcp-discovery',
            args: { serverKey, tools: tools.length },
            timestamp: Date.now(),
            slackDelegated: false,
            timer: setTimeout(() => {
              if (pending.has(id)) {
                pending.delete(id);
                broadcast('remove', { id, decision: 'deny' });
              }
            }, 60_000), // 60s timeout for discovery
            waiter: null,
            earlyDecision: null,
          };
          pending.set(id, entry);
          broadcast('add', {
            id,
            type: 'mcp-discovery',
            serverKey,
            mcpTools: tools,
            toolName: 'mcp-discovery',
            args: { serverKey, toolCount: tools.length },
          });
        }

        res.writeHead(200).end();
        return;
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    if (req.method === 'POST' && pathname === '/mcp/large-response') {
      if (req.headers['x-node9-internal'] !== internalToken) return res.writeHead(403).end();
      try {
        const body = JSON.parse(await readBody(req)) as {
          toolName?: unknown;
          serverKey?: unknown;
          originalBytes?: unknown;
        };
        const event: LargeResponseEvent = {
          ts: new Date().toISOString(),
          toolName: String(body.toolName ?? 'unknown'),
          serverKey: String(body.serverKey ?? ''),
          originalBytes: Number(body.originalBytes) || 0,
        };
        largeResponseRing.push(event);
        if (largeResponseRing.length > LARGE_RESPONSE_RING_SIZE) largeResponseRing.shift();
        broadcast('mcp-large-response', event);
        res.writeHead(200).end();
        return;
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    if (req.method === 'POST' && pathname === '/mcp/approve') {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const { id, serverKey, disabledTools } = JSON.parse(await readBody(req));
        const entry = pending.get(id);
        if (!entry || entry.type !== 'mcp-discovery' || entry.serverKey !== serverKey) {
          res.writeHead(404).end();
          return;
        }

        clearTimeout(entry.timer);
        approveServer(serverKey, disabledTools);
        appendAuditLog({
          toolName: `mcp-server:${serverKey}`,
          args: { disabledTools },
          decision: 'allow',
        });
        pending.delete(id);
        broadcast('remove', { id, decision: 'allow' });
        res.writeHead(200).end();
        return;
      } catch {
        res.writeHead(400).end();
        return;
      }
    }

    // GET /mcp/status/<serverKey> — removed in v3 sprint. The gateway
    // used to poll this while waiting for the user to approve new MCP
    // tools in the browser. No more browser; first-connect pins
    // automatically and rug-pull is caught by mcp-pin.

    res.writeHead(404).end();
  });

  setDaemonServer(server);

  // ── Port Conflict Resolution ─────────────────────────────────────────────
  //
  // The retry below MUST be bounded. Unbounded, a foreign process on the port (a
  // dev server, a rebound socket) puts this daemon in a permanent ~1 Hz loop:
  //   EADDRINUSE → no pid file → probe /settings → not a daemon → listen() → …
  // never serving, never exiting, and never recording anything beyond 'starting'.
  let bindAttempts = 0;
  const MAX_BIND_ATTEMPTS = 3;
  function retryListen(): void {
    if (++bindAttempts >= MAX_BIND_ATTEMPTS) {
      logDaemonStartup(
        'port-unavailable',
        `:${DAEMON_PORT} is held by something that is not a node9 daemon`
      );
      recordStartupState(
        'failed',
        'port-unavailable',
        `:${DAEMON_PORT} is held by another process that is not a node9 daemon — free the port, then: node9 daemon --background`
      );
      // exit 0, NOT 1: under Restart=on-failure a non-zero exit turns a permanently
      // occupied port into a restart storm. This is a stable, explained condition.
      return process.exit(0);
    }
    server.listen(DAEMON_PORT, DAEMON_HOST);
  }

  server.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code === 'EADDRINUSE') {
      try {
        if (fs.existsSync(DAEMON_PID_FILE)) {
          const { pid } = JSON.parse(fs.readFileSync(DAEMON_PID_FILE, 'utf-8'));
          process.kill(pid, 0); // Throws if process is dead
          logDaemonStartup('port-in-use', `another daemon (pid ${pid}) owns :${DAEMON_PORT}`);
          // A healthy daemon owns the port and its pid file names it — nothing wrong.
          recordStartupState('ok-elsewhere');
          return process.exit(0);
        }
      } catch {
        // The pid file names a dead process (or is corrupt): drop it and retry.
        // BOUNDED, via retryListen: the unlink can FAIL (read-only dir, permissions)
        // and is swallowed here, in which case the next EADDRINUSE lands back on
        // this same branch — an infinite loop. An earlier version of this fix left
        // this site unbounded, reasoning that removing the pid file makes it
        // converge; that assumed an operation that can fail.
        try {
          fs.unlinkSync(DAEMON_PID_FILE);
        } catch {}
        retryListen();
        return;
      }

      // No PID file but port is in use — orphaned daemon from a previous run.
      fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/settings`, {
        signal: AbortSignal.timeout(1000),
      })
        .then((res) => {
          if (res.ok) {
            // Try to recover the orphan's PID and re-create the PID file so
            // future stop/status calls can find it. Try `ss` first (Linux,
            // fast); fall back to `lsof` (macOS + portable Linux).
            let adopted = false;
            try {
              let orphanPid: number | null = null;
              const ss = spawnSync('ss', ['-Htnp', `sport = :${DAEMON_PORT}`], {
                encoding: 'utf8',
                timeout: 1000,
              });
              if (!ss.error && ss.status === 0) {
                const m = ss.stdout?.match(/pid=(\d+)/);
                if (m) orphanPid = parseInt(m[1], 10);
              } else if (
                (ss.error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT' ||
                ss.status === null
              ) {
                const lsof = spawnSync(
                  'lsof',
                  ['-nP', `-iTCP:${DAEMON_PORT}`, '-sTCP:LISTEN', '-t'],
                  { encoding: 'utf8', timeout: 1000 }
                );
                if (!lsof.error && lsof.status === 0) {
                  const first = (lsof.stdout ?? '').split('\n')[0].trim();
                  if (/^\d+$/.test(first)) orphanPid = parseInt(first, 10);
                }
              }
              if (orphanPid !== null) {
                process.kill(orphanPid, 0);
                atomicWriteSync(
                  DAEMON_PID_FILE,
                  JSON.stringify({ pid: orphanPid, port: DAEMON_PORT, internalToken, autoStarted }),
                  { mode: 0o600 }
                );
                adopted = true;
              }
            } catch {}
            // The two outcomes here are NOT the same, and recording them
            // identically is how a silent failure loop gets built:
            if (adopted) {
              // A healthy daemon owns the port and the pid file now names it.
              logDaemonStartup(
                'port-in-use-orphan',
                `adopted the daemon already on :${DAEMON_PORT}`
              );
              recordStartupState('ok-elsewhere');
            } else {
              // Something holds the port but we could not identify it (no ss/lsof,
              // or the pid is not ours to signal), so NO pid file was written —
              // and every CLI keeps reporting "daemon not running" while each new
              // start exits 0 right here. That loop is invisible unless it is
              // recorded as the failure it is.
              // NB: this branch is gated on /settings answering OK, so the daemon
              // on the port is provably HEALTHY — it just could not be identified
              // (no `ss`/`lsof`, or its pid is not ours to signal). Telling the
              // user to kill it would be wrong; the problem is only that every
              // pid-file-based command will keep reporting "not running".
              logDaemonStartup(
                'orphan-unidentified',
                `healthy daemon on :${DAEMON_PORT} could not be identified — no pid file written`
              );
              recordStartupState(
                'failed',
                'orphan-unidentified',
                `a healthy daemon is running on :${DAEMON_PORT} but its process could not be identified, so node9 cannot track it — install \`ss\` or \`lsof\`, or restart it with: node9 daemon --background`
              );
            }
            process.exit(0);
          } else {
            // Something answered on the port but it is not a healthy daemon.
            retryListen();
          }
        })
        .catch(() => {
          // Nothing answered (timeout / refused) — the holder is not a daemon.
          retryListen();
        });
      return;
    }
    logDaemonStartup('bind-failed', e.message);
    recordStartupState('failed', 'bind-failed', e.message);
    console.error(chalk.red('\n🛑 Node9 Daemon Error:'), e.message);
    process.exit(1);
  });

  // Safety net: an unhandled rejection in the async request handler must never
  // crash the daemon and disconnect all SSE clients.
  if (!daemonRejectionHandlerRegistered) {
    markRejectionHandlerRegistered();
    process.on('unhandledRejection', (reason) => {
      const stack = reason instanceof Error ? reason.stack : String(reason);
      console.error(chalk.red('[node9 daemon] unhandled rejection — keeping daemon alive:'), stack);
    });
  }

  server.listen(DAEMON_PORT, DAEMON_HOST, () => {
    atomicWriteSync(
      DAEMON_PID_FILE,
      JSON.stringify({ pid: process.pid, port: DAEMON_PORT, internalToken, autoStarted }),
      { mode: 0o600 }
    );
    console.error(chalk.green(`🛡️  Node9 Guard LIVE on 127.0.0.1:${DAEMON_PORT}`));
    // Record the SUCCESS, not just the failures. daemon-startup.log is append-only
    // and the auto-start path pipes this process's stderr into it, so without a
    // terminating "it worked" entry an old crash stays the newest recognisable
    // line forever — and doctor would blame a months-dead ERR_REQUIRE_ESM for a
    // daemon that has started cleanly a hundred times since.
    logDaemonStartup('ok', `listening on ${DAEMON_HOST}:${DAEMON_PORT}`);
    recordStartupState('ok');
  });

  // ── Flight Recorder ──────────────────────────────────────────────────────
  if (watchMode) {
    console.error(chalk.cyan('🛰️  Flight Recorder active — daemon will not idle-timeout'));
  }
  startActivitySocket();
}
