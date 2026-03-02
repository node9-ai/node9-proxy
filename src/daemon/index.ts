// src/daemon/index.ts — Node9 localhost approval server
import { UI_HTML_TEMPLATE } from './ui';
import http from 'http';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { randomUUID } from 'crypto';
import chalk from 'chalk';

export const DAEMON_PORT = 7391;
export const DAEMON_HOST = '127.0.0.1';
const homeDir = os.homedir();
export const DAEMON_PID_FILE = path.join(homeDir, '.node9', 'daemon.pid');
export const DECISIONS_FILE = path.join(homeDir, '.node9', 'decisions.json');
const GLOBAL_CONFIG_FILE = path.join(homeDir, '.node9', 'config.json');
const CREDENTIALS_FILE = path.join(homeDir, '.node9', 'credentials.json');

interface AuditEntry {
  toolName: string;
  args: unknown;
  decision: string;
  timestamp: number;
}

export const AUDIT_LOG_FILE = path.join(homeDir, '.node9', 'audit.log');

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

function appendAuditLog(data: {
  toolName: string;
  args: unknown;
  decision: string;
  timestamp: number;
}): void {
  try {
    const entry = JSON.stringify({ ...data, args: redactArgs(data.args) }) + '\n';
    const dir = path.dirname(AUDIT_LOG_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(AUDIT_LOG_FILE, entry);
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

function readGlobalSettings(): {
  autoStartDaemon: boolean;
  slackEnabled: boolean;
  agentMode: boolean;
} {
  try {
    if (fs.existsSync(GLOBAL_CONFIG_FILE)) {
      const config = JSON.parse(fs.readFileSync(GLOBAL_CONFIG_FILE, 'utf-8')) as Record<
        string,
        unknown
      >;
      const s = (config?.settings as Record<string, unknown>) ?? {};
      return {
        autoStartDaemon: s.autoStartDaemon !== false,
        slackEnabled: s.slackEnabled !== false,
        agentMode: s.agentMode === true,
      };
    }
  } catch {}
  return { autoStartDaemon: true, slackEnabled: true, agentMode: false };
}

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
  const dir = path.dirname(GLOBAL_CONFIG_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(GLOBAL_CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
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
  waiter: ((d: Decision) => void) | null;
  earlyDecision: Decision | null;
}

const pending = new Map<string, PendingEntry>();
const sseClients = new Set<http.ServerResponse>();
let abandonTimer: ReturnType<typeof setTimeout> | null = null;
let daemonServer: http.Server | null = null;

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
    const opts = { stdio: 'ignore' as const };
    if (process.platform === 'darwin') execSync(`open "${url}"`, opts);
    else if (process.platform === 'win32') execSync(`cmd /c start "" "${url}"`, opts);
    else execSync(`xdg-open "${url}"`, opts);
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
    const dir = path.dirname(DECISIONS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const decisions = readPersistentDecisions();
    decisions[toolName] = decision;
    fs.writeFileSync(DECISIONS_FILE, JSON.stringify(decisions, null, 2));
    broadcast('decisions', decisions);
  } catch {}
}

export function startDaemon(): void {
  const csrfToken = randomUUID();
  const internalToken = randomUUID();
  const UI_HTML = UI_HTML_TEMPLATE.replace('{{CSRF_TOKEN}}', csrfToken);
  const validToken = (req: http.IncomingMessage) => req.headers['x-node9-token'] === csrfToken;

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
          abandonTimer = setTimeout(abandonPending, 2000);
        }
      });
    }

    if (req.method === 'POST' && pathname === '/check') {
      try {
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
                timestamp: Date.now(),
              });
              if (e.waiter) e.waiter('deny');
              else e.earlyDecision = 'deny';
              pending.delete(id);
              broadcast('remove', { id });
            }
          }, AUTO_DENY_MS),
        };
        pending.set(id, entry);
        broadcast('add', {
          id,
          toolName,
          args,
          slackDelegated: entry.slackDelegated,
          agent: entry.agent,
          mcpServer: entry.mcpServer,
        });
        if (sseClients.size === 0) openBrowser(`http://127.0.0.1:${DAEMON_PORT}/`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ id }));
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'GET' && pathname.startsWith('/wait/')) {
      const id = pathname.split('/').pop()!;
      const entry = pending.get(id);
      if (!entry) return res.writeHead(404).end();
      if (entry.earlyDecision) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ decision: entry.earlyDecision }));
      }
      entry.waiter = (d) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ decision: d }));
      };
      return;
    }

    if (req.method === 'POST' && pathname.startsWith('/decision/')) {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const id = pathname.split('/').pop()!;
        const entry = pending.get(id);
        if (!entry) return res.writeHead(404).end();
        const { decision, persist } = JSON.parse(await readBody(req));
        if (persist) writePersistentDecision(entry.toolName, decision);
        appendAuditLog({
          toolName: entry.toolName,
          args: entry.args,
          decision,
          timestamp: Date.now(),
        });
        clearTimeout(entry.timer);
        if (entry.waiter) entry.waiter(decision);
        else entry.earlyDecision = decision;
        pending.delete(id!);
        broadcast('remove', { id });
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'GET' && pathname === '/settings') {
      const s = readGlobalSettings();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ...s, autoStarted }));
    }

    if (req.method === 'POST' && pathname === '/settings') {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const body = await readBody(req);
        const data = JSON.parse(body);
        if (data.autoStartDaemon !== undefined)
          writeGlobalSetting('autoStartDaemon', data.autoStartDaemon);
        if (data.slackEnabled !== undefined) writeGlobalSetting('slackEnabled', data.slackEnabled);
        if (data.agentMode !== undefined) writeGlobalSetting('agentMode', data.agentMode);
        res.writeHead(200);
        return res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400).end();
      }
    }

    if (req.method === 'GET' && pathname === '/slack-status') {
      const s = readGlobalSettings();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ hasKey: hasStoredSlackKey(), enabled: s.slackEnabled }));
    }

    if (req.method === 'POST' && pathname === '/slack-key') {
      if (!validToken(req)) return res.writeHead(403).end();
      try {
        const { apiKey } = JSON.parse(await readBody(req));
        if (!fs.existsSync(path.dirname(CREDENTIALS_FILE)))
          fs.mkdirSync(path.dirname(CREDENTIALS_FILE), { recursive: true });
        fs.writeFileSync(
          CREDENTIALS_FILE,
          JSON.stringify({ apiKey, apiUrl: 'https://api.node9.ai/api/v1/intercept' }, null, 2),
          { mode: 0o600 }
        );
        broadcast('slack-status', { hasKey: true, enabled: readGlobalSettings().slackEnabled });
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
        fs.writeFileSync(DECISIONS_FILE, JSON.stringify(decisions, null, 2));
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
          timestamp: Date.now(),
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
  server.listen(DAEMON_PORT, DAEMON_HOST, () => {
    if (!fs.existsSync(path.dirname(DAEMON_PID_FILE)))
      fs.mkdirSync(path.dirname(DAEMON_PID_FILE), { recursive: true });
    fs.writeFileSync(
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
