// src/daemon/server.ts
// HTTP server for the Node9 localhost approval daemon.
// All route handlers live here; shared state is in daemon/state.ts.
import http from 'http';
import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { spawnSync } from 'child_process';
import chalk from 'chalk';
import { authorizeHeadless, getGlobalSettings, getConfig, _resetConfigCache } from '../core';
import { SHIELDS, readActiveShields, writeActiveShields } from '../shields';
import { UI_HTML_TEMPLATE } from './ui';
import {
  DAEMON_PORT,
  DAEMON_HOST,
  DAEMON_PID_FILE,
  DECISIONS_FILE,
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
  hasStoredSlackKey,
  writeGlobalSetting,
  writeTrustEntry,
  readPersistentDecisions,
  writePersistentDecision,
  readBody,
  openBrowser,
  broadcast,
  abandonPending,
  startActivitySocket,
  type PendingEntry,
  type SseClient,
  type Decision,
  CREDENTIALS_FILE,
  suggestionTracker,
  suggestions,
  taintStore,
  insightCounts,
  loadInsightCounts,
  saveInsightCounts,
} from './state';
import { patchConfig, GLOBAL_CONFIG_PATH, type ConfigPatch } from '../config/patch.js';
import { SmartRuleSchema } from '../config-schema.js';

export function startDaemon(): void {
  loadInsightCounts(); // restore persisted nudge counters across restarts
  const csrfToken = randomUUID();
  const internalToken = randomUUID();
  const UI_HTML = UI_HTML_TEMPLATE.replace('{{CSRF_TOKEN}}', csrfToken);
  const validToken = (req: http.IncomingMessage) => req.headers['x-node9-token'] === csrfToken;

  // ── Graceful Idle Timeout ────────────────────────────────────────────────
  const IDLE_TIMEOUT_MS = 12 * 60 * 60 * 1000; // 12 hours
  const watchMode = process.env.NODE9_WATCH_MODE === '1';
  let idleTimer: NodeJS.Timeout | undefined;
  // Track if we've already opened the browser this session so we don't
  // open duplicate tabs when node9 tail is also running (tail is an SSE
  // client, so sseClients.size > 0 even when no browser is open).
  let browserOpened = false;
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

    if (req.method === 'GET' && pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(UI_HTML);
    }

    if (req.method === 'GET' && pathname === '/events') {
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
      res.write(`event: decisions\ndata: ${JSON.stringify(readPersistentDecisions())}\n\n`);
      const activeShields = readActiveShields();
      res.write(
        `event: shields-status\ndata: ${JSON.stringify({
          shields: Object.values(SHIELDS).map((s) => ({
            name: s.name,
            description: s.description,
            active: activeShields.includes(s.name),
          })),
        })}\n\n`
      );
      // Emit the CSRF token on every connection so reconnecting clients
      // (including the terminal racer) can acquire it without a browser tab.
      res.write(`event: csrf\ndata: ${JSON.stringify({ token: csrfToken })}\n\n`);
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

    // Tail notifies the daemon that it already opened the browser so the daemon
    // won't open a duplicate tab on the first /check request.
    // Uses the internal token (from daemon.pid) so only node9 CLI tools can call this —
    // not arbitrary local processes that don't have access to the PID file.
    if (req.method === 'POST' && pathname === '/browser-opened') {
      if (req.headers['x-node9-internal'] !== internalToken) return res.writeHead(403).end();
      browserOpened = true;
      res.writeHead(200).end();
      return;
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
          fromCLI = false,
          activityId,
          cwd,
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
            slackDelegated: entry.slackDelegated,
            agent: entry.agent,
            mcpServer: entry.mcpServer,
            interactive: terminalEnabled,
            // allowCount = what this count will be if the user allows.
            // Terminal uses this to show the 💡 insight line on the Nth consecutive approval.
            allowCount: (insightCounts.get(toolName) ?? 0) + 1,
          });
          // Only the `node9 check` path (autoStartDaemonAndWait) pre-opens the
          // browser before registering the request — it signals this via
          // NODE9_BROWSER_OPENED=1 so we don't open a duplicate tab.
          const browserAlreadyOpened = process.env.NODE9_BROWSER_OPENED === '1';
          if (browserEnabled && !browserOpened && !browserAlreadyOpened) {
            browserOpened = true;
            openBrowser(`http://127.0.0.1:${DAEMON_PORT}/`);
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id, allowCount: (insightCounts.get(toolName) ?? 0) + 1 }));

        // Run the full policy + cloud + native pipeline in the background.
        // Browser and terminal racers are skipped (no TTY, browser card already exists via SSE).
        // Skip when slackDelegated: the hook process already owns the cloud race for this
        // request — running a second initNode9SaaS here would create a duplicate pending
        // cloud request that never gets resolved.
        if (slackDelegated) return;
        authorizeHeadless(
          toolName,
          args,
          {
            agent: typeof agent === 'string' ? agent : undefined,
            mcpServer: typeof mcpServer === 'string' ? mcpServer : undefined,
          },
          { calledFromDaemon: true }
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
          writeTrustEntry(entry.toolName, ms);
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
        // Track human allow decisions. After threshold consecutive allows for
        // the same tool, broadcast a suggestion card to reduce future friction.
        // Reset the counter on deny so we never suggest allowing blocked actions.
        if (resolvedDecision === 'allow' && !persist) {
          insightCounts.set(entry.toolName, (insightCounts.get(entry.toolName) ?? 0) + 1);
          saveInsightCounts();
          const suggestion = suggestionTracker.recordAllow(entry.toolName, entry.args);
          if (suggestion) {
            suggestions.set(suggestion.id, suggestion);
            broadcast('suggestion:new', suggestion);
          }
        } else if (resolvedDecision === 'deny') {
          insightCounts.delete(entry.toolName);
          saveInsightCounts();
          suggestionTracker.resetTool(entry.toolName);
        }

        // source is validated against an allowlist AFTER appendAuditLog so the
        // raw user-supplied value never reaches any log string — no log injection.
        const VALID_SOURCES = new Set(['terminal', 'browser', 'native']);
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

    if (req.method === 'GET' && pathname === '/slack-status') {
      try {
        const s = getGlobalSettings();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ hasKey: hasStoredSlackKey(), enabled: s.slackEnabled }));
      } catch (err) {
        console.error(chalk.red('[node9 daemon] GET /slack-status failed:'), err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'internal' }));
      }
    }

    if (req.method === 'POST' && pathname === '/slack-key') {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const { apiKey } = JSON.parse(await readBody(req));
        atomicWriteSync(
          CREDENTIALS_FILE,
          JSON.stringify({ apiKey, apiUrl: 'https://api.node9.ai/api/v1/intercept' }, null, 2),
          { mode: 0o600 }
        );
        broadcast('slack-status', { hasKey: true, enabled: getGlobalSettings().slackEnabled });
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'DELETE' && pathname.startsWith('/decisions/')) {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const toolName = decodeURIComponent(pathname.split('/').pop()!);
        const decisions = readPersistentDecisions();
        delete decisions[toolName];
        atomicWriteSync(DECISIONS_FILE, JSON.stringify(decisions, null, 2));
        broadcast('decisions', decisions);
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

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

        // ── Event Bridge: track human decisions for Smart Rule Suggestions ────
        // insightCounts tracks all human approvals (including cloud/Slack) so the
        // 💡 insight line appears consistently across all approval channels.
        // suggestionTracker is gated on !slackDelegated — Slack auto-approvals should
        // not generate smart rule suggestions (different UX intent).
        if (resolvedResolveDecision === 'allow') {
          insightCounts.set(entry.toolName, (insightCounts.get(entry.toolName) ?? 0) + 1);
          saveInsightCounts();
        } else {
          insightCounts.delete(entry.toolName);
          saveInsightCounts();
        }
        if (!entry.slackDelegated) {
          if (resolvedResolveDecision === 'allow') {
            const suggestion = suggestionTracker.recordAllow(entry.toolName, entry.args);
            if (suggestion) {
              suggestions.set(suggestion.id, suggestion);
              broadcast('suggestion:new', suggestion);
            }
          } else {
            suggestionTracker.resetTool(entry.toolName);
          }
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
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true }));
    }

    if (req.method === 'GET' && pathname === '/audit') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(getAuditHistory()));
    }

    if (req.method === 'GET' && pathname === '/shields') {
      if (!validToken(req)) return res.writeHead(403).end();
      const active = readActiveShields();
      const shields = Object.values(SHIELDS).map((s) => ({
        name: s.name,
        description: s.description,
        active: active.includes(s.name),
      }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ shields }));
    }

    if (req.method === 'POST' && pathname === '/shields') {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const { name, active } = JSON.parse(await readBody(req)) as {
          name: string;
          active: boolean;
        };
        if (!SHIELDS[name]) return res.writeHead(400).end();
        const current = readActiveShields();
        const updated = active
          ? [...new Set([...current, name])]
          : current.filter((n) => n !== name);
        writeActiveShields(updated);
        _resetConfigCache();
        const shieldsPayload = Object.values(SHIELDS).map((s) => ({
          name: s.name,
          description: s.description,
          active: updated.includes(s.name),
        }));
        broadcast('shields-status', { shields: shieldsPayload });
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    // ── Suggestions routes ────────────────────────────────────────────────────

    if (req.method === 'GET' && pathname === '/suggestions') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify([...suggestions.values()]));
    }

    if (
      req.method === 'POST' &&
      pathname.startsWith('/suggestions/') &&
      pathname.endsWith('/apply')
    ) {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const body = await readBody(req);
        const data = body ? (JSON.parse(body) as { configPath?: string; rule?: unknown }) : {};
        const configPath = data.configPath ?? GLOBAL_CONFIG_PATH;

        // Clamp configPath to ~/.node9/ before touching anything else — path.resolve
        // neutralises any .. traversal so a crafted body cannot write outside the
        // node9 config directory. Check happens before suggestion lookup so it is
        // testable without a pre-existing suggestion in memory.
        const node9Dir = path.dirname(GLOBAL_CONFIG_PATH); // ~/.node9
        if (!path.resolve(configPath).startsWith(node9Dir + path.sep)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(
            JSON.stringify({ error: 'configPath must be within the node9 config directory' })
          );
        }

        const id = pathname.split('/')[2];
        const suggestion = suggestions.get(id);
        if (!suggestion) return res.writeHead(404).end();

        // Allow the UI to override the rule before applying — validate against schema first
        // to prevent a malformed rule from corrupting the config file.
        let patch: ConfigPatch;
        if (data.rule !== undefined) {
          const parsed = SmartRuleSchema.safeParse(data.rule);
          if (!parsed.success) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: parsed.error.message }));
          }
          patch = { type: 'smartRule', rule: parsed.data };
        } else {
          patch = suggestion.suggestedRule as ConfigPatch;
        }

        patchConfig(configPath, patch);
        _resetConfigCache();

        // Reset insight counter for this tool — the rule now handles it automatically,
        // so re-nudging immediately would cause a redundant suggestion on the next call.
        insightCounts.delete(suggestion.toolName);
        saveInsightCounts();

        suggestion.status = 'applied';
        broadcast('suggestion:resolved', { id, status: 'applied' });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        console.error(chalk.red('[node9 daemon] POST /suggestions/:id/apply failed:'), err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: String(err) }));
      }
    }

    if (
      req.method === 'POST' &&
      pathname.startsWith('/suggestions/') &&
      pathname.endsWith('/dismiss')
    ) {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const id = pathname.split('/')[2];
        const suggestion = suggestions.get(id);
        if (!suggestion) return res.writeHead(404).end();

        suggestion.status = 'dismissed';
        broadcast('suggestion:resolved', { id, status: 'dismissed' });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

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
        };
        if (typeof body.path !== 'string' || typeof body.source !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'path and source are required strings' }));
        }
        const ttlMs = typeof body.ttlMs === 'number' ? body.ttlMs : undefined;
        taintStore.taint(body.path, body.source, ttlMs);
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

    res.writeHead(404).end();
  });

  setDaemonServer(server);

  // ── Port Conflict Resolution ─────────────────────────────────────────────
  server.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code === 'EADDRINUSE') {
      try {
        if (fs.existsSync(DAEMON_PID_FILE)) {
          const { pid } = JSON.parse(fs.readFileSync(DAEMON_PID_FILE, 'utf-8'));
          process.kill(pid, 0); // Throws if process is dead
          return process.exit(0);
        }
      } catch {
        try {
          fs.unlinkSync(DAEMON_PID_FILE);
        } catch {}
        server.listen(DAEMON_PORT, DAEMON_HOST);
        return;
      }

      // No PID file but port is in use — orphaned daemon from a previous run.
      fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/settings`, {
        signal: AbortSignal.timeout(1000),
      })
        .then((res) => {
          if (res.ok) {
            try {
              const r = spawnSync('ss', ['-Htnp', `sport = :${DAEMON_PORT}`], {
                encoding: 'utf8',
                timeout: 1000,
              });
              const match = r.stdout?.match(/pid=(\d+)/);
              if (match) {
                const orphanPid = parseInt(match[1], 10);
                process.kill(orphanPid, 0);
                atomicWriteSync(
                  DAEMON_PID_FILE,
                  JSON.stringify({ pid: orphanPid, port: DAEMON_PORT, internalToken, autoStarted }),
                  { mode: 0o600 }
                );
              }
            } catch {}
            process.exit(0);
          } else {
            server.listen(DAEMON_PORT, DAEMON_HOST);
          }
        })
        .catch(() => {
          server.listen(DAEMON_PORT, DAEMON_HOST);
        });
      return;
    }
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
    console.error(chalk.green(`🛡️  Node9 Guard LIVE: http://127.0.0.1:${DAEMON_PORT}`));
  });

  // ── Flight Recorder ──────────────────────────────────────────────────────
  if (watchMode) {
    console.error(chalk.cyan('🛰️  Flight Recorder active — daemon will not idle-timeout'));
  }
  startActivitySocket();
}
