// src/daemon/index.ts — Node9 localhost approval server
import { UI_HTML_TEMPLATE } from './ui';
import http from 'http';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawn } from 'child_process';
import { randomUUID } from 'crypto';
import chalk from 'chalk';
import { authorizeHeadless, getGlobalSettings, getConfig } from '../core';

export const DAEMON_PORT = 7391;
export const DAEMON_HOST = '127.0.0.1';
const homeDir = os.homedir();
export const DAEMON_PID_FILE = path.join(homeDir, '.node9', 'daemon.pid');
export const DECISIONS_FILE = path.join(homeDir, '.node9', 'decisions.json');
const GLOBAL_CONFIG_FILE = path.join(homeDir, '.node9', 'config.json');
const CREDENTIALS_FILE = path.join(homeDir, '.node9', 'credentials.json');

interface AuditEntry {
  ts: string;
  tool: string;
  args: unknown;
  decision: string;
  source: string;
}

export const AUDIT_LOG_FILE = path.join(homeDir, '.node9', 'audit.log');
const TRUST_FILE = path.join(homeDir, '.node9', 'trust.json');

// ── Atomic File Writer (Fixes Task 0.1) ──────────────────────────────────
function atomicWriteSync(filePath: string, data: string, options?: fs.WriteFileOptions): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${filePath}.${randomUUID()}.tmp`;
  fs.writeFileSync(tmpPath, data, options);
  fs.renameSync(tmpPath, filePath);
}

function writeTrustEntry(toolName: string, durationMs: number): void {
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

const TRUST_DURATIONS: Record<string, number> = {
  '30m': 30 * 60_000,
  '1h': 60 * 60_000,
  '2h': 2 * 60 * 60_000,
};

const SECRET_KEY_RE = /password|secret|token|key|apikey|credential|auth/i;

function redactArgs(value: unknown): unknown {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(redactArgs);
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    result[k] = SECRET_KEY_RE.test(k) ? '[REDACTED]' : redactArgs(v);
  }
  return result;
}

function appendAuditLog(data: { toolName: string; args: unknown; decision: string }): void {
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

function getAuditHistory(limit = 20): AuditEntry[] {
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

const AUTO_DENY_MS = 120_000;

function getOrgName(): string | null {
  try {
    if (fs.existsSync(CREDENTIALS_FILE)) {
      return 'Node9 Cloud';
    }
  } catch {}
  return null;
}

// True when the daemon was launched automatically by the hook/smart-runner.
const autoStarted = process.env.NODE9_AUTO_STARTED === '1';

function hasStoredSlackKey(): boolean {
  return fs.existsSync(CREDENTIALS_FILE);
}

function writeGlobalSetting(key: string, value: unknown): void {
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

type Decision = 'allow' | 'deny' | 'abandoned';

interface PendingEntry {
  id: string;
  toolName: string;
  args: unknown;
  agent?: string;
  mcpServer?: string;
  timestamp: number;
  slackDelegated: boolean;
  timer: ReturnType<typeof setTimeout>;
  waiter: ((d: Decision, reason?: string) => void) | null;
  earlyDecision: Decision | null;
  earlyReason?: string;
}

const pending = new Map<string, PendingEntry>();
const sseClients = new Set<http.ServerResponse>();
let abandonTimer: ReturnType<typeof setTimeout> | null = null;
let daemonServer: http.Server | null = null;
let hadBrowserClient = false; // true once at least one SSE client has connected

function abandonPending() {
  abandonTimer = null;
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
      daemonServer?.close();
      process.exit(0);
    }, 200);
  }
}

function broadcast(event: string, data: unknown) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach((client) => {
    try {
      client.write(msg);
    } catch {
      sseClients.delete(client);
    }
  });
}

function openBrowser(url: string) {
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

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => resolve(body));
  });
}

function readPersistentDecisions(): Record<string, 'allow' | 'deny'> {
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

function writePersistentDecision(toolName: string, decision: 'allow' | 'deny') {
  try {
    const decisions = readPersistentDecisions();
    decisions[toolName] = decision;
    atomicWriteSync(DECISIONS_FILE, JSON.stringify(decisions, null, 2));
    broadcast('decisions', decisions);
  } catch {}
}

export function startDaemon(): void {
  const csrfToken = randomUUID();
  const internalToken = randomUUID();
  const UI_HTML = UI_HTML_TEMPLATE.replace('{{CSRF_TOKEN}}', csrfToken);
  const validToken = (req: http.IncomingMessage) => req.headers['x-node9-token'] === csrfToken;

  // ── Graceful Idle Timeout (Fixes Task 0.4) ──────────────────────────────
  const IDLE_TIMEOUT_MS = 12 * 60 * 60 * 1000; // 12 hours
  let idleTimer: NodeJS.Timeout;
  function resetIdleTimer() {
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

  const server = http.createServer(async (req, res) => {
    const { pathname } = new URL(req.url || '/', `http://${req.headers.host}`);

    if (req.method === 'GET' && pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(UI_HTML);
    }

    if (req.method === 'GET' && pathname === '/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      if (abandonTimer) {
        clearTimeout(abandonTimer);
        abandonTimer = null;
      }
      hadBrowserClient = true;
      sseClients.add(res);
      res.write(
        `event: init\ndata: ${JSON.stringify({
          requests: Array.from(pending.values()).map((e) => ({
            id: e.id,
            toolName: e.toolName,
            args: e.args,
            slackDelegated: e.slackDelegated,
            timestamp: e.timestamp,
            agent: e.agent,
            mcpServer: e.mcpServer,
          })),
          orgName: getOrgName(),
          autoDenyMs: AUTO_DENY_MS,
        })}\n\n`
      );
      res.write(`event: decisions\ndata: ${JSON.stringify(readPersistentDecisions())}\n\n`);
      return req.on('close', () => {
        sseClients.delete(res);
        if (sseClients.size === 0 && pending.size > 0) {
          // Give 10s if browser was already open (page reload / brief disconnect),
          // 15s on cold-start (browser needs time to open and connect SSE).
          // 2s was too short: auto-opened browsers often reconnect SSE mid-load,
          // causing a disconnect+reconnect that exceeded the 2s window and
          // abandoned the pending request before the user could see it.
          abandonTimer = setTimeout(abandonPending, hadBrowserClient ? 10_000 : 15_000);
        }
      });
    }

    if (req.method === 'POST' && pathname === '/check') {
      try {
        resetIdleTimer(); // Agent is active, reset the shutdown clock

        const body = await readBody(req);
        if (body.length > 65_536) return res.writeHead(413).end();
        const { toolName, args, slackDelegated = false, agent, mcpServer } = JSON.parse(body);
        const id = randomUUID();
        const entry: PendingEntry = {
          id,
          toolName,
          args,
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
              broadcast('remove', { id });
            }
          }, AUTO_DENY_MS),
        };
        pending.set(id, entry);
        const browserEnabled = getConfig().settings.approvers?.browser !== false;
        if (browserEnabled) {
          broadcast('add', {
            id,
            toolName,
            args,
            slackDelegated: entry.slackDelegated,
            agent: entry.agent,
            mcpServer: entry.mcpServer,
          });
          // When auto-started, the CLI already called openBrowserLocal() before
          // the request was registered, so the browser is already opening.
          // Skip here to avoid opening a duplicate tab.
          if (sseClients.size === 0 && !autoStarted)
            openBrowser(`http://127.0.0.1:${DAEMON_PORT}/`);
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id }));

        // Run the full policy + cloud + native pipeline in the background.
        // Browser and terminal racers are skipped (no TTY, browser card already exists via SSE).
        authorizeHeadless(
          toolName,
          args,
          false,
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

            clearTimeout(e.timer);
            const decision: Decision = result.approved ? 'allow' : 'deny';
            appendAuditLog({ toolName: e.toolName, args: e.args, decision });
            if (e.waiter) {
              // Python is already waiting on GET /wait/:id — respond and clean up
              e.waiter(decision, result.reason);
              pending.delete(id);
              broadcast('remove', { id });
            } else {
              // Python hasn't sent GET /wait/:id yet — set earlyDecision and leave
              // the entry alive so the GET handler can find it and respond
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
            broadcast('remove', { id });
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
        pending.delete(id);
        broadcast('remove', { id });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        const body: { decision: Decision; reason?: string } = { decision: entry.earlyDecision };
        if (entry.earlyReason) body.reason = entry.earlyReason;
        return res.end(JSON.stringify(body));
      }
      entry.waiter = (d, reason?) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        const body: { decision: Decision; reason?: string } = { decision: d };
        if (reason) body.reason = reason;
        res.end(JSON.stringify(body));
      };
      return;
    }

    if (req.method === 'POST' && pathname.startsWith('/decision/')) {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const id = pathname.split('/').pop()!;
        const entry = pending.get(id);
        if (!entry) return res.writeHead(404).end();
        const { decision, persist, trustDuration, reason } = JSON.parse(await readBody(req)) as {
          decision: string;
          persist?: boolean;
          trustDuration?: string;
          reason?: string;
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
          if (entry.waiter) entry.waiter('allow');
          else entry.earlyDecision = 'allow';
          pending.delete(id);
          broadcast('remove', { id });
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
        if (entry.waiter) entry.waiter(resolvedDecision, reason);
        else {
          entry.earlyDecision = resolvedDecision;
          entry.earlyReason = reason;
        }
        pending.delete(id!);
        broadcast('remove', { id });
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'GET' && pathname === '/settings') {
      const s = getGlobalSettings();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ...s, autoStarted }));
    }

    // ── Updated POST /settings to handle new config schema ─────────────────
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
      const s = getGlobalSettings();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ hasKey: hasStoredSlackKey(), enabled: s.slackEnabled }));
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
        const { decision } = JSON.parse(await readBody(req));
        appendAuditLog({
          toolName: entry.toolName,
          args: entry.args,
          decision,
        });
        clearTimeout(entry.timer);
        if (entry.waiter) entry.waiter(decision);
        else entry.earlyDecision = decision;
        pending.delete(id);
        broadcast('remove', { id });
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'GET' && pathname === '/audit') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(getAuditHistory()));
    }

    res.writeHead(404).end();
  });

  daemonServer = server;

  // ── Port Conflict Resolution (Fixes Task 0.2) ───────────────────────────
  server.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code === 'EADDRINUSE') {
      try {
        if (fs.existsSync(DAEMON_PID_FILE)) {
          const { pid } = JSON.parse(fs.readFileSync(DAEMON_PID_FILE, 'utf-8'));
          process.kill(pid, 0); // Throws if process is dead
          // If we reach here, a legitimate daemon is running. Safely exit.
          return process.exit(0);
        }
      } catch {
        // Zombie PID detected. Clean up and resurrect server.
        try {
          fs.unlinkSync(DAEMON_PID_FILE);
        } catch {}
        server.listen(DAEMON_PORT, DAEMON_HOST);
        return;
      }
    }
    console.error(chalk.red('\n🛑 Node9 Daemon Error:'), e.message);
    process.exit(1);
  });

  server.listen(DAEMON_PORT, DAEMON_HOST, () => {
    atomicWriteSync(
      DAEMON_PID_FILE,
      JSON.stringify({ pid: process.pid, port: DAEMON_PORT, internalToken, autoStarted }),
      { mode: 0o600 }
    );
    console.log(chalk.green(`🛡️  Node9 Guard LIVE: http://127.0.0.1:${DAEMON_PORT}`));
  });
}

export function stopDaemon(): void {
  if (!fs.existsSync(DAEMON_PID_FILE)) return console.log(chalk.yellow('Not running.'));
  try {
    const { pid } = JSON.parse(fs.readFileSync(DAEMON_PID_FILE, 'utf-8'));
    process.kill(pid, 'SIGTERM');
    console.log(chalk.green('✅ Stopped.'));
  } catch {
    console.log(chalk.gray('Cleaned up stale PID file.'));
  } finally {
    try {
      fs.unlinkSync(DAEMON_PID_FILE);
    } catch {}
  }
}

export function daemonStatus(): void {
  if (!fs.existsSync(DAEMON_PID_FILE))
    return console.log(chalk.yellow('Node9 daemon: not running'));
  try {
    const { pid } = JSON.parse(fs.readFileSync(DAEMON_PID_FILE, 'utf-8'));
    process.kill(pid, 0);
    console.log(chalk.green('Node9 daemon: running'));
  } catch {
    console.log(chalk.yellow('Node9 daemon: not running (stale PID)'));
  }
}
