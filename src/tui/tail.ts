// src/tui/tail.ts — Terminal Flight Recorder
import http from 'http';
import chalk from 'chalk';
import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { spawn } from 'child_process';
import { DAEMON_PORT } from '../daemon';

const PID_FILE = path.join(os.homedir(), '.node9', 'daemon.pid');

const ICONS: Record<string, string> = {
  bash: '💻',
  shell: '💻',
  terminal: '💻',
  read: '📖',
  edit: '✏️',
  write: '✏️',
  glob: '📂',
  grep: '🔍',
  agent: '🤖',
  search: '🔍',
  sql: '🗄️',
  query: '🗄️',
  list: '📂',
  delete: '🗑️',
  web: '🌐',
};

function getIcon(tool: string): string {
  const t = tool.toLowerCase();
  for (const [k, v] of Object.entries(ICONS)) {
    if (t.includes(k)) return v;
  }
  return '🛠️';
}

interface ActivityItem {
  id: string;
  tool: string;
  args: unknown;
  ts: number;
}

interface ResultItem {
  id: string;
  status: string;
  label?: string;
}

export interface TailOptions {
  history?: boolean;
  clear?: boolean;
}

function formatBase(activity: ActivityItem): string {
  const time = new Date(activity.ts).toLocaleTimeString([], { hour12: false });
  const icon = getIcon(activity.tool);
  const toolName = activity.tool.slice(0, 16).padEnd(16);
  const argsStr = JSON.stringify(activity.args ?? {}).replace(/\s+/g, ' ');
  const argsPreview = argsStr.length > 70 ? argsStr.slice(0, 70) + '…' : argsStr;
  return `${chalk.gray(time)} ${icon} ${chalk.white.bold(toolName)} ${chalk.dim(argsPreview)}`;
}

function renderResult(activity: ActivityItem, result: ResultItem): void {
  const base = formatBase(activity);
  let status: string;
  if (result.status === 'allow') {
    status = chalk.green('✓ ALLOW');
  } else if (result.status === 'dlp') {
    status = chalk.bgRed.white.bold(' 🛡️  DLP ');
  } else {
    status = chalk.red('✗ BLOCK');
  }

  if (process.stdout.isTTY) {
    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);
  }
  console.log(`${base}  ${status}`);
}

function renderPending(activity: ActivityItem): void {
  if (!process.stdout.isTTY) return;
  process.stdout.write(`${formatBase(activity)}  ${chalk.yellow('● …')}\r`);
}

async function ensureDaemon(): Promise<number> {
  // Read the port from PID file if it exists, then verify the daemon is alive
  let pidPort: number | null = null;
  if (fs.existsSync(PID_FILE)) {
    try {
      const { port } = JSON.parse(fs.readFileSync(PID_FILE, 'utf-8')) as { port: number };
      pidPort = port;
    } catch {
      // Corrupt or unreadable PID file — fall back to DAEMON_PORT for the health check
      console.error(chalk.dim('⚠️  Could not read PID file; falling back to default port.'));
    }
  }

  // Health check — covers both PID-file and orphaned daemon cases
  const checkPort = pidPort ?? DAEMON_PORT;
  try {
    const res = await fetch(`http://127.0.0.1:${checkPort}/settings`, {
      signal: AbortSignal.timeout(500),
    });
    if (res.ok) return checkPort;
  } catch {}

  // Not running — start it in the background
  console.log(chalk.dim('🛡️  Starting Node9 daemon...'));
  const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
    detached: true,
    stdio: 'ignore',
    env: { ...process.env, NODE9_AUTO_STARTED: '1' },
  });
  child.unref();

  // Wait up to 5s for it to be ready
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 250));
    try {
      const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/settings`, {
        signal: AbortSignal.timeout(500),
      });
      if (res.ok) return DAEMON_PORT;
    } catch {}
  }

  console.error(chalk.red('❌ Daemon failed to start. Try: node9 daemon start'));
  process.exit(1);
}

export async function startTail(options: TailOptions = {}): Promise<void> {
  const port = await ensureDaemon();

  if (options.clear) {
    const result = await new Promise<{ ok: boolean; code?: string }>((resolve) => {
      const req = http.request(
        { method: 'POST', hostname: '127.0.0.1', port, path: '/events/clear' },
        (res) => {
          const status = res.statusCode ?? 0;
          // Attach 'end' before resume() so the event is never missed on fast responses
          res.on('end', () =>
            resolve({
              ok: status >= 200 && status < 300,
              code: status >= 200 && status < 300 ? undefined : `HTTP ${status}`,
            })
          );
          res.resume();
        }
      );
      // Register error handler before setTimeout so it is always in place before
      // any path that calls req.destroy() (timeout or caller abort).
      req.once('error', (err: NodeJS.ErrnoException) => resolve({ ok: false, code: err.code }));
      req.setTimeout(2000, () => {
        // resolve() before destroy() so the promise settles as ETIMEDOUT first.
        // destroy() may subsequently emit an error (e.g. ECONNRESET), but
        // req.once ensures the listener is already consumed by then — preventing
        // a second resolve(). Node.js guarantees no listener fires between a
        // synchronous resolve() and the next event-loop tick, so there is no
        // unhandled-rejection window here.
        resolve({ ok: false, code: 'ETIMEDOUT' });
        req.destroy();
      });
      req.end();
    });
    if (result.ok) {
      console.log(chalk.green('✓ Flight Recorder buffer cleared.'));
    } else if (result.code === 'ECONNREFUSED') {
      throw new Error('Daemon is not running. Start it with: node9 daemon start');
    } else if (result.code === 'ETIMEDOUT') {
      throw new Error('Daemon did not respond in time. Try: node9 daemon restart');
    } else {
      throw new Error(`Failed to clear buffer (${result.code ?? 'unknown error'})`);
    }
    return;
  }

  const connectionTime = Date.now();
  const pending = new Map<string, ActivityItem>();

  console.log(chalk.cyan.bold(`\n🛰️  Node9 tail  `) + chalk.dim(`→ localhost:${port}`));
  if (options.history) {
    console.log(chalk.dim('Showing history + live events. Press Ctrl+C to exit.\n'));
  } else {
    console.log(
      chalk.dim('Showing live events only. Use --history to include past. Press Ctrl+C to exit.\n')
    );
  }

  process.on('SIGINT', () => {
    if (process.stdout.isTTY) {
      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
    }
    console.log(chalk.dim('\n🛰️  Disconnected.'));
    process.exit(0);
  });

  const req = http.get(`http://127.0.0.1:${port}/events`, (res) => {
    if (res.statusCode !== 200) {
      console.error(chalk.red(`Failed to connect: HTTP ${res.statusCode}`));
      process.exit(1);
    }

    // Spec-compliant SSE parser: accumulate fields per message block
    let currentEvent = '';
    let currentData = '';
    res.on('error', () => {}); // handled by rl 'close'
    const rl = readline.createInterface({ input: res, crlfDelay: Infinity });
    rl.on('error', () => {}); // suppress — 'close' fires next and handles exit

    rl.on('line', (line) => {
      if (line.startsWith('event:')) {
        currentEvent = line.slice(6).trim();
      } else if (line.startsWith('data:')) {
        currentData = line.slice(5).trim();
      } else if (line === '') {
        // Message boundary — process accumulated fields
        if (currentEvent && currentData) {
          handleMessage(currentEvent, currentData);
        }
        currentEvent = '';
        currentData = '';
      }
    });

    rl.on('close', () => {
      if (process.stdout.isTTY) {
        readline.clearLine(process.stdout, 0);
        readline.cursorTo(process.stdout, 0);
      }
      console.log(chalk.red('\n❌ Daemon disconnected.'));
      process.exit(1);
    });
  });

  function handleMessage(event: string, rawData: string): void {
    let data: ActivityItem & ResultItem;
    try {
      data = JSON.parse(rawData) as ActivityItem & ResultItem;
    } catch {
      return;
    }

    if (event === 'activity') {
      // History filter: skip replayed events unless --history requested
      if (!options.history && data.ts > 0 && data.ts < connectionTime) return;

      // Ring-buffer replay: activity events already have a resolved status — render immediately
      if (data.status && data.status !== 'pending') {
        renderResult(data, data);
        return;
      }

      pending.set(data.id, data);

      // Show pending indicator immediately for slow operations (bash, sql, agent)
      const slowTool = /bash|shell|query|sql|agent/i.test(data.tool);
      if (slowTool) renderPending(data);
    }

    if (event === 'activity-result') {
      const original = pending.get(data.id);
      if (original) {
        renderResult(original, data);
        pending.delete(data.id);
      }
    }
  }

  req.on('error', (err: NodeJS.ErrnoException) => {
    const msg =
      err.code === 'ECONNREFUSED'
        ? 'Daemon is not running. Start it with: node9 daemon start'
        : err.message;
    console.error(chalk.red(`\n❌ ${msg}`));
    process.exit(1);
  });
}
