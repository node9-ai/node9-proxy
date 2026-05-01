// src/tui/tail.ts — Terminal Flight Recorder + Interactive Approvals
import http from 'http';
import chalk from 'chalk';
import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { spawn, execSync } from 'child_process';
import { DAEMON_PORT } from '../daemon';
import { getInternalToken } from '../auth/daemon';
import { getConfig } from '../core';

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
  status?: string;
  costEstimate?: number;
  agent?: string;
  mcpServer?: string;
}

interface ResultItem {
  id: string;
  status: string;
  label?: string;
  costEstimate?: number;
}

interface ApprovalRequest {
  id: string;
  toolName: string;
  args: unknown;
  agent?: string;
  riskMetadata?: {
    tier?: number;
    blockedByLabel?: string;
    matchedField?: string;
    matchedWord?: string;
    ruleName?: string;
    ruleDescription?: string;
  };
  /** When set, shows the [1]/[2]/[3] recovery menu instead of the standard [y/n/a/t] prompt. */
  recoveryCommand?: string;
  /**
   * When true, the card is informational only — the tty menu in the hook process is the
   * decision maker. Tail shows context + "awaiting tty" message, no keypress.
   */
  viewOnly?: boolean;
  timestamp?: number;
  /** How many consecutive allows (including this one) if approved. Used for 💡 insight. */
  allowCount?: number;
}

export interface TailOptions {
  history?: boolean;
  clear?: boolean;
}

// ── Context fill monitor ──────────────────────────────────────────────────────

const MODEL_CONTEXT_LIMITS: Record<string, number> = {
  'claude-opus-4': 200000,
  'claude-sonnet-4': 200000,
  'claude-haiku-4': 200000,
  'claude-3-7': 200000,
  'claude-3-5': 200000,
};

function getModelContextLimit(model: string): number {
  const base = model.replace(/@.*$/, '').replace(/-\d{8}$/, '');
  for (const [key, limit] of Object.entries(MODEL_CONTEXT_LIMITS)) {
    if (base.startsWith(key)) return limit;
  }
  return 200000;
}

interface SessionUsage {
  inputTokens: number;
  outputTokens: number;
  model: string;
  fillPct: number;
}

function readSessionUsage(): SessionUsage | null {
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  if (!fs.existsSync(projectsDir)) return null;

  let latestFile: string | null = null;
  let latestMtime = 0;

  try {
    for (const dir of fs.readdirSync(projectsDir)) {
      const dirPath = path.join(projectsDir, dir);
      try {
        if (!fs.statSync(dirPath).isDirectory()) continue;
        for (const file of fs.readdirSync(dirPath)) {
          if (!file.endsWith('.jsonl') || file.startsWith('agent-')) continue;
          const filePath = path.join(dirPath, file);
          try {
            const mtime = fs.statSync(filePath).mtimeMs;
            if (mtime > latestMtime) {
              latestMtime = mtime;
              latestFile = filePath;
            }
          } catch {}
        }
      } catch {}
    }
  } catch {}

  if (!latestFile) return null;

  try {
    const lines = fs.readFileSync(latestFile, 'utf-8').split('\n');
    let lastModel = '';
    let lastInput = 0;
    let lastOutput = 0;
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const entry = JSON.parse(line) as {
          type?: string;
          message?: {
            model?: string;
            usage?: {
              input_tokens?: number;
              output_tokens?: number;
              cache_creation_input_tokens?: number;
              cache_read_input_tokens?: number;
            };
          };
        };
        if (entry.type !== 'assistant' || !entry.message?.usage) continue;
        const u = entry.message.usage;
        lastInput =
          (u.input_tokens ?? 0) +
          (u.cache_read_input_tokens ?? 0) +
          (u.cache_creation_input_tokens ?? 0);
        lastOutput = u.output_tokens ?? 0;
        if (entry.message.model) lastModel = entry.message.model;
      } catch {}
    }
    if (!lastModel || lastInput === 0) return null;
    const limit = getModelContextLimit(lastModel);
    const fillPct = Math.round((lastInput / limit) * 100);
    return { inputTokens: lastInput, outputTokens: lastOutput, model: lastModel, fillPct };
  } catch {
    return null;
  }
}

function formatContextStat(stat: SessionUsage): string {
  const pctColor = stat.fillPct >= 80 ? chalk.red : stat.fillPct >= 50 ? chalk.yellow : chalk.cyan;
  const k = (n: number) => `${Math.round(n / 1000)}k`;
  const modelShort = stat.model
    .replace(/@.*$/, '')
    .replace(/-\d{8}$/, '')
    .replace(/^claude-/, '');
  return (
    chalk.dim('ctx: ') +
    pctColor(`${stat.fillPct}%`) +
    chalk.dim(
      ` (${k(stat.inputTokens)}/${k(getModelContextLimit(stat.model))}  out ${k(stat.outputTokens)}  · ${modelShort})`
    )
  );
}

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const RESET = '\x1B[0m';
const BOLD = '\x1B[1m';
const RED = '\x1B[31m';
const YELLOW = '\x1B[33m';
const CYAN = '\x1B[36m';
const GRAY = '\x1B[90m';
const GREEN = '\x1B[32m';
const HIDE_CURSOR = '\x1B[?25l';
const SHOW_CURSOR = '\x1B[?25h';
const ERASE_DOWN = '\x1B[J';

// ── Activity feed rendering ───────────────────────────────────────────────────

/** Strip ANSI escape codes to get the printable length of a string. */
function visibleLength(s: string): number {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1B\[[0-9;]*m/g, '').length;
}

/**
 * How many terminal lines does `text` occupy when written to stdout?
 * Returns 1 when the terminal width is unknown (non-TTY or columns=0).
 */
function wrappedLineCount(text: string): number {
  const cols = process.stdout.columns;
  if (!cols) return 1;
  const len = visibleLength(text);
  return Math.max(1, Math.ceil(len / cols));
}

// Track which pending item is currently shown and how many lines it occupies.
let pendingShownForId: string | null = null;
let pendingWrappedLines = 0;

function agentLabel(agent: string | undefined, mcpServer?: string): string {
  if (!agent || agent === 'Terminal') {
    // Even without an agent, surface the MCP server when present (e.g. direct
    // gateway invocation without clientInfo). Otherwise blank as before.
    return mcpServer ? chalk.dim(`[→ ${mcpServer}] `) : '';
  }
  const short =
    agent === 'Claude Code'
      ? 'Claude'
      : agent === 'Gemini CLI'
        ? 'Gemini'
        : agent === 'Unknown Agent'
          ? ''
          : agent.split(' ')[0];
  if (!short) return mcpServer ? chalk.dim(`[→ ${mcpServer}] `) : '';
  return mcpServer ? chalk.dim(`[${short} → ${mcpServer}] `) : chalk.dim(`[${short}] `);
}

function formatBase(activity: ActivityItem): string {
  const time = new Date(activity.ts).toLocaleTimeString([], { hour12: false });
  const icon = getIcon(activity.tool);
  const toolName = activity.tool.slice(0, 16).padEnd(16);
  const argsStr = JSON.stringify(activity.args ?? {})
    .replace(/\s+/g, ' ')
    .replaceAll(os.homedir(), '~');
  const argsPreview = argsStr.length > 70 ? argsStr.slice(0, 70) + '…' : argsStr;
  return `${chalk.gray(time)} ${icon} ${agentLabel(activity.agent, activity.mcpServer)}${chalk.white.bold(toolName)} ${chalk.dim(argsPreview)}`;
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

  const cost = result.costEstimate ?? activity.costEstimate;
  const costSuffix =
    cost == null ? '' : chalk.dim(`  ~$${cost >= 0.001 ? cost.toFixed(3) : '0.000'}`);

  if (process.stdout.isTTY) {
    if (pendingShownForId === activity.id && pendingWrappedLines > 1) {
      // Pending content wrapped onto multiple lines. Move up to the first of
      // those wrapped lines, then erase everything from there to end-of-screen.
      readline.moveCursor(process.stdout, 0, -(pendingWrappedLines - 1));
      readline.cursorTo(process.stdout, 0);
      process.stdout.write(ERASE_DOWN);
    } else {
      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
    }
    pendingShownForId = null;
    pendingWrappedLines = 0;
  }
  console.log(`${base}  ${status}${costSuffix}`);
}

function renderPending(activity: ActivityItem): void {
  if (!process.stdout.isTTY) return;
  const line = `${formatBase(activity)}  ${chalk.yellow('● …')}`;
  pendingShownForId = activity.id;
  pendingWrappedLines = wrappedLineCount(line);
  process.stdout.write(`${line}\r`);
}

// ── Daemon startup ────────────────────────────────────────────────────────────

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

// ── POST /decision ────────────────────────────────────────────────────────────

function postDecisionHttp(
  id: string,
  decision: 'allow' | 'deny' | 'trust',
  csrfToken: string,
  port: number,
  opts?: { persist?: boolean; trustDuration?: string; reason?: string; source?: string }
): Promise<void> {
  return new Promise((resolve, reject) => {
    const bodyObj: Record<string, unknown> = { decision, source: opts?.source ?? 'terminal' };
    if (opts?.persist) bodyObj.persist = true;
    if (opts?.trustDuration) bodyObj.trustDuration = opts.trustDuration;
    if (opts?.reason) bodyObj.reason = opts.reason;
    const body = JSON.stringify(bodyObj);
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: `/decision/${id}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'X-Node9-Token': csrfToken,
        },
      },
      (res) => {
        res.resume();
        // 200 = success, 409 = idempotent conflict (another racer already decided) — both ok
        if (res.statusCode === 200 || res.statusCode === 409) resolve();
        else reject(new Error(`POST /decision returned ${res.statusCode}`));
      }
    );
    req.on('error', reject);
    req.end(body);
  });
}

// ── Approval card ─────────────────────────────────────────────────────────────

const DIVIDER = '─'.repeat(60);

/** Extract the most human-readable summary from tool args. */
function extractArgsSummary(toolName: string, args: unknown): string {
  const a = args as Record<string, unknown> | null;
  if (!a) return '';
  // Bash / shell — show the raw command, not JSON
  const cmd = a['command'] ?? a['cmd'];
  if (typeof cmd === 'string') return cmd.replace(/\s+/g, ' ').trim();
  // File tools — show the path
  const fp = a['file_path'] ?? a['path'] ?? a['filepath'];
  if (typeof fp === 'string') return fp;
  // SQL / query tools
  const q = a['query'] ?? a['sql'];
  if (typeof q === 'string') return q.replace(/\s+/g, ' ').trim();
  // Generic: JSON but strip outer braces for brevity
  const s = JSON.stringify(a).replace(/\s+/g, ' ');
  return s.length > 80 ? s.slice(0, 80) + '…' : s;
}

/** Strip redundant shield suffix from reason strings.
 * "Pipe-to-shell is dangerous — blocked by bash-safe shield" → "Pipe-to-shell is dangerous" */
function cleanReason(raw: string): string {
  return raw
    .replace(/\s*[—–-]+\s*(blocked by|requires human approval)[^)]*(\([^)]*\))?\.?\s*$/i, '')
    .trim();
}

/** Strip technical prefixes from blockedByLabel for display.
 * "Smart Rule: shield:bash-safe:block-pipe-to-shell" → "bash-safe" */
function cleanBlockedBy(raw: string): string {
  // "Smart Rule: shield:X:rule-name" → "X"
  const shieldMatch = raw.match(/shield:([^:]+):/i);
  if (shieldMatch) return shieldMatch[1];
  // "Smart Rule: my-rule-name" → "my-rule-name"
  const smartMatch = raw.match(/^Smart Rule:\s*(.+)$/i);
  if (smartMatch) return smartMatch[1];
  return raw;
}

function buildCardLines(req: ApprovalRequest, localCount: number = 0): string[] {
  // Recovery menu: stateful rule with a recoveryCommand uses a different card layout
  if (req.recoveryCommand) {
    return buildRecoveryCardLines(req);
  }

  const argsSummary = extractArgsSummary(req.toolName, req.args);
  const argsPreview = argsSummary.length > 72 ? argsSummary.slice(0, 72) + '…' : argsSummary;

  const rawBlockedBy = req.riskMetadata?.blockedByLabel ?? 'Policy rule';
  const blockedBy = cleanBlockedBy(rawBlockedBy);
  const isBlock = req.riskMetadata?.tier != null && req.riskMetadata.tier <= 2;
  const severityIcon = isBlock ? `${RED}🛑` : `${YELLOW}⚠ `;

  // Human-readable description: prefer ruleDescription, fall back to blockedByLabel
  const rawDesc = req.riskMetadata?.ruleDescription ?? '';
  const description = rawDesc ? cleanReason(rawDesc) : '';

  const agentSuffix =
    req.agent && req.agent !== 'Terminal' ? ` ${RESET}${chalk.dim(`(${req.agent})`)}` : '';

  const lines: string[] = [
    ``,
    `${BOLD}${CYAN}╔══ Node9 Approval Required ══╗${RESET}`,
    `${CYAN}║${RESET} Tool:    ${BOLD}${req.toolName}${RESET}${agentSuffix}`,
    `${CYAN}║${RESET} Policy:  ${severityIcon} ${blockedBy}${RESET}`,
  ];

  if (description) {
    lines.push(`${CYAN}║${RESET} Why:     ${YELLOW}${description}${RESET}`);
  }

  // Taint warning
  if (req.riskMetadata?.ruleName && rawBlockedBy.includes('Taint')) {
    lines.push(`${CYAN}║${RESET} ${YELLOW}⚠  ${req.riskMetadata.ruleName}${RESET}`);
  }

  if (argsPreview) {
    const argLabel = req.toolName.toLowerCase().includes('bash') ? 'Command' : 'Args   ';
    lines.push(`${CYAN}║${RESET} ${argLabel}:  ${GRAY}${argsPreview}${RESET}`);
  }

  // 💡 Insight: show after 2+ prior terminal approvals for this tool (i.e. the 3rd prompt onward)
  if (localCount >= 2) {
    lines.push(
      `${CYAN}║${RESET} ${YELLOW}💡${RESET} Approved ${localCount}× before — ${BOLD}[a]${RESET}${YELLOW} creates a permanent rule${RESET}`
    );
  }

  lines.push(
    `${CYAN}╚${RESET}`,
    ``,
    `  ${BOLD}${GREEN}[↵/y]${RESET} Allow   ${BOLD}${RED}[n]${RESET} Deny   ${BOLD}${YELLOW}[a]${RESET} Always Allow   ${BOLD}${CYAN}[t]${RESET} Trust 30m`,
    ``
  );

  return lines;
}

/** Recovery menu card — rendered when a stateful smart rule provides a recoveryCommand. */
function buildRecoveryCardLines(req: ApprovalRequest): string[] {
  const argsObj = req.args as Record<string, unknown> | null;
  const command =
    typeof argsObj?.command === 'string'
      ? argsObj.command
      : JSON.stringify(req.args ?? {})
          .replace(/\s+/g, ' ')
          .slice(0, 60);
  const ruleName = req.riskMetadata?.ruleName?.replace(/^Smart Rule:\s*/i, '') ?? 'policy rule';
  const recoveryCommand = req.recoveryCommand!;

  const interactiveLines = req.viewOnly
    ? [`  ${GRAY}→ Awaiting decision from interactive terminal...${RESET}`]
    : [
        `  ${BOLD}${GREEN}[1]${RESET} Allow anyway  ${GRAY}(override policy)${RESET}`,
        `  ${BOLD}${YELLOW}[2]${RESET} Redirect AI: "Run '${recoveryCommand}' first, then retry"`,
        `  ${BOLD}${RED}[3]${RESET} Deny & stop  ${GRAY}(hard block)${RESET}`,
        ``,
        `  ${GRAY}[Timeout: auto-deny]${RESET}`,
        `  Select [1-3]: `,
      ];

  return [
    ``,
    `${BOLD}${CYAN}${DIVIDER}${RESET}`,
    `🛡️  ${BOLD}NODE9 STATE GUARD:${RESET} '${BOLD}${command}${RESET}'`,
    `${YELLOW}⚠️  Rule: ${ruleName}${RESET}`,
    `${CYAN}${DIVIDER}${RESET}`,
    ...(!req.viewOnly ? [`${BOLD}What would you like to do?${RESET}`, ``] : []),
    ...interactiveLines,
    `${CYAN}${DIVIDER}${RESET}`,
    ``,
  ];
}

// ── Approver helpers ─────────────────────────────────────────────────────────

function readApproversFromDisk(): Record<string, boolean> {
  const configPath = path.join(os.homedir(), '.node9', 'config.json');
  try {
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
    const settings = (raw.settings ?? {}) as Record<string, unknown>;
    return (settings.approvers ?? {}) as Record<string, boolean>;
  } catch {
    return {};
  }
}

function approverStatusLine(): string {
  const a = readApproversFromDisk();
  const fmt = (label: string, key: string): string => {
    const on = a[key] !== false;
    return `[${key[0]}]${label.slice(1)} ${on ? chalk.green('✓') : chalk.dim('✗')}`;
  };
  return `${fmt('native', 'native')}  ${fmt('browser', 'browser')}  ${fmt('cloud', 'cloud')}  ${fmt('terminal', 'terminal')}`;
}

function toggleApprover(channel: string): void {
  const configPath = path.join(os.homedir(), '.node9', 'config.json');
  try {
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
    const settings = (raw.settings ?? {}) as Record<string, unknown>;
    const approvers = (settings.approvers ?? {}) as Record<string, boolean>;
    approvers[channel] = approvers[channel] === false; // flip: false→true, true/undefined→false
    settings.approvers = approvers;
    raw.settings = settings;
    fs.writeFileSync(configPath, JSON.stringify(raw, null, 2) + '\n');
  } catch (err) {
    process.stderr.write(`[node9] toggleApprover failed: ${String(err)}\n`);
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

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
  // True until the first live (pending) event arrives — ring buffer replay events
  // are shown regardless of timestamp so the user always sees recent history on connect.
  let initialReplayDone = false;
  const activityPending = new Map<string, ActivityItem>();
  // Buffer for results that arrive before their matching pending event (race condition)
  const orphanedResults = new Map<string, ResultItem>();

  // ── Approval state ──────────────────────────────────────────────────────────
  let csrfToken = '';
  const approvalQueue: ApprovalRequest[] = [];
  let cardActive = false;
  // Number of lines the current card occupies (for clearing)
  let cardLineCount = 0;
  // Called when an external event (native popup, browser) resolves the active card
  let cancelActiveCard: ((externalDecision?: 'allow' | 'deny') => void) | null = null;
  // Local consecutive-allow counter per toolName — tracks THIS terminal's approvals
  // so the 💡 insight fires reliably regardless of native popup / browser racing.
  const localAllowCounts = new Map<string, number>();

  const canApprove = process.stdout.isTTY && process.stdin.isTTY;
  // Enable keypress event parsing on stdin (idempotent — safe to call multiple times)
  if (canApprove) readline.emitKeypressEvents(process.stdin);

  // ── Idle keypress handler — active between cards, handles approver toggles ──
  type KeyCb = (str: string, key: { name?: string; ctrl?: boolean }) => void;
  let idleKeypressHandler: KeyCb | null = null;

  function enterIdleMode(): void {
    if (!canApprove || idleKeypressHandler !== null) return;
    try {
      process.stdin.setRawMode(true);
    } catch {
      return;
    }
    process.stdin.resume();
    idleKeypressHandler = (_str: string, key: { name?: string; ctrl?: boolean }) => {
      const name = key?.name ?? '';
      if (key?.ctrl && name === 'c') {
        process.kill(process.pid, 'SIGINT');
        return;
      }
      if (name === 'q') {
        process.kill(process.pid, 'SIGINT');
        return;
      }
      const channel =
        name === 'n'
          ? 'native'
          : name === 'b'
            ? 'browser'
            : name === 'c'
              ? 'cloud'
              : name === 't'
                ? 'terminal'
                : null;
      if (channel) {
        toggleApprover(channel);
        console.log(chalk.dim(`  Approvers: ${approverStatusLine()}`));
      }
    };
    process.stdin.on('keypress', idleKeypressHandler);
  }

  function exitIdleMode(): void {
    if (idleKeypressHandler) {
      process.stdin.removeListener('keypress', idleKeypressHandler);
      idleKeypressHandler = null;
    }
    try {
      process.stdin.setRawMode(false);
    } catch {
      /* ignore */
    }
    process.stdin.pause();
  }

  function clearCard(): void {
    if (cardLineCount > 0) {
      // Use cursor-up instead of RESTORE_CURSOR so scrolling doesn't orphan lines.
      // RESTORE_CURSOR saves screen coordinates; if the terminal scrolled while the
      // card was showing, the saved row points to the wrong content and ERASE_DOWN
      // misses the card's top line, causing a visible duplicate on external resolve.
      readline.moveCursor(process.stdout, 0, -cardLineCount);
      process.stdout.write(ERASE_DOWN);
      cardLineCount = 0;
    }
  }

  function printCard(req: ApprovalRequest): void {
    process.stdout.write(HIDE_CURSOR);
    // Seed localAllowCounts from the daemon value when it's higher.
    // This handles cross-session persistence (tail restart) while keeping local
    // increments so the insight stays visible even after the suggestion threshold resets.
    const daemonPrior = req.allowCount !== undefined ? req.allowCount - 1 : 0;
    const localPrior = localAllowCounts.get(req.toolName) ?? 0;
    const priorCount = Math.max(daemonPrior, localPrior);
    const lines = buildCardLines(req, priorCount);
    for (const line of lines) process.stdout.write(line + '\n');
    cardLineCount = lines.length;
  }

  function showNextCard(): void {
    if (cardActive || approvalQueue.length === 0 || !canApprove) return;
    exitIdleMode();

    // Attempt raw mode BEFORE rendering the card — if it fails we bail silently
    // rather than leaving a stranded card with no key handler attached.
    try {
      process.stdin.setRawMode(true);
    } catch {
      cardActive = false;
      enterIdleMode();
      return;
    }

    cardActive = true;
    const req = approvalQueue[0];
    printCard(req);

    let settled = false;
    type KeypressCb = (str: string, key: { name?: string; ctrl?: boolean }) => void;
    let onKeypress: KeypressCb | null = null;

    const cleanup = () => {
      const handler = onKeypress;
      onKeypress = null;
      if (handler) process.stdin.removeListener('keypress', handler);
      cancelActiveCard = null;
      enterIdleMode();
    };

    const settle = (action: 'allow' | 'deny' | 'always-allow' | 'trust' | 'redirect') => {
      if (settled) return;
      settled = true;
      cleanup();
      // Stamp the decision onto the card in place (keeps card visible in scrollback).
      // clearCard() moves cursor up to card start and erases; then reprint with stamp.
      clearCard();
      const stampedLines = buildCardLines(
        req,
        Math.max(
          req.allowCount !== undefined ? req.allowCount - 1 : 0,
          localAllowCounts.get(req.toolName) ?? 0
        )
      );
      const decisionStamp =
        action === 'always-allow'
          ? chalk.yellow('★ ALWAYS ALLOW')
          : action === 'trust'
            ? chalk.cyan('⏱ TRUST 30m')
            : action === 'allow'
              ? chalk.green('✓ ALLOWED')
              : action === 'redirect'
                ? chalk.yellow('↩ REDIRECT AI')
                : chalk.red('✗ DENIED');
      stampedLines.push(`  ${BOLD}→${RESET} ${decisionStamp} ${GRAY}(terminal)${RESET}`, ``);
      for (const line of stampedLines) process.stdout.write(line + '\n');
      process.stdout.write(SHOW_CURSOR);
      cardLineCount = 0;

      // Update local consecutive-allow counter for this toolName
      if (action === 'allow' || action === 'always-allow' || action === 'trust') {
        localAllowCounts.set(req.toolName, (localAllowCounts.get(req.toolName) ?? 0) + 1);
      } else if (action === 'deny' || action === 'redirect') {
        localAllowCounts.delete(req.toolName);
      }

      // Map action to decision + options for the daemon
      let httpDecision: 'allow' | 'deny' | 'trust';
      let httpOpts:
        | { persist?: boolean; trustDuration?: string; reason?: string; source?: string }
        | undefined;
      if (action === 'always-allow') {
        httpDecision = 'allow';
        httpOpts = { persist: true };
      } else if (action === 'trust') {
        httpDecision = 'trust';
        httpOpts = { trustDuration: '30m' };
      } else if (action === 'redirect') {
        // Choice [2]: deny with a redirect reason that the race engine surfaces to Claude
        httpDecision = 'deny';
        const recoveryCommand = req.recoveryCommand ?? 'the required pre-condition';
        const redirectReason =
          `USER INTERVENTION: I am blocking this ${req.toolName} because the required ` +
          `pre-condition has not been met. Please execute \`${recoveryCommand}\`. ` +
          `If it passes, you are then authorized to run \`${req.toolName}\`.`;
        httpOpts = { reason: redirectReason, source: 'terminal-redirect' };
      } else {
        httpDecision = action;
      }

      // POST decision best-effort; 409 = another racer already won
      postDecisionHttp(req.id, httpDecision, csrfToken, port, httpOpts).catch((err) => {
        try {
          fs.appendFileSync(
            path.join(os.homedir(), '.node9', 'hook-debug.log'),
            `[tail] POST /decision failed: ${String(err)}\n`
          );
        } catch {
          /* ignore */
        }
      });

      // Decision is already stamped on the card above — no separate activity line needed.

      approvalQueue.shift();
      cardActive = false;
      showNextCard();
    };

    // Exposed so the 'remove' SSE event can dismiss the card when another
    // racer (native popup, browser) already resolved the request.
    cancelActiveCard = (externalDecision?: 'allow' | 'deny') => {
      if (settled) return;
      settled = true;
      cleanup();
      // Stamp the card with the external decision so it stays in scrollback.
      clearCard();
      const priorCount = Math.max(
        req.allowCount !== undefined ? req.allowCount - 1 : 0,
        localAllowCounts.get(req.toolName) ?? 0
      );
      const stampedLines = buildCardLines(req, priorCount);
      if (externalDecision) {
        const source =
          externalDecision === 'allow' ? chalk.green('✓ ALLOWED') : chalk.red('✗ DENIED');
        stampedLines.push(`  ${BOLD}→${RESET} ${source} ${GRAY}(external)${RESET}`, ``);
      }
      for (const line of stampedLines) process.stdout.write(line + '\n');
      process.stdout.write(SHOW_CURSOR);
      cardLineCount = 0;
      approvalQueue.shift();
      cardActive = false;
      showNextCard();
    };

    // viewOnly cards are informational — the hook's tty menu is the decision maker.
    // Don't attach keypress; the card will be dismissed via cancelActiveCard when
    // the daemon broadcasts 'remove' after check.ts calls resolveViaDaemon.
    if (req.viewOnly) {
      process.stdin.resume();
      onKeypress = () => {}; // absorb keypresses silently while card is shown
      process.stdin.on('keypress', onKeypress);
      return;
    }

    process.stdin.resume();
    // Use keypress events (requires emitKeypressEvents called at startup) —
    // more reliable than raw 'data' buffer parsing across Node.js versions.
    onKeypress = (_str: string, key: { name?: string; ctrl?: boolean }) => {
      const name = key?.name ?? '';
      if (req.recoveryCommand) {
        // Recovery menu: only [1]/[2]/[3] are valid
        if (name === '1') {
          settle('allow');
        } else if (name === '2') {
          settle('redirect');
        } else if (name === '3' || (key?.ctrl && name === 'c')) {
          settle('deny');
        }
      } else {
        // Standard approval card
        if (name === 'y' || name === 'return') {
          settle('allow');
        } else if (name === 'n' || name === 'd' || (key?.ctrl && name === 'c')) {
          settle('deny');
        } else if (name === 'a') {
          settle('always-allow');
        } else if (name === 't') {
          settle('trust');
        }
      }
    };
    process.stdin.on('keypress', onKeypress);
  }

  const dashboardUrl = `http://127.0.0.1:${port}/`;

  // Open the browser dashboard from the foreground process — more reliable than
  // the daemon's detached spawn. Use execSync so failures throw and are caught.
  // getConfig() reads the actual project config (approvers.browser), unlike
  // GET /settings which only returns global settings and never includes approvers.
  try {
    const browserEnabled = getConfig().settings.approvers?.browser !== false;
    if (browserEnabled) {
      if (process.platform === 'darwin') execSync(`open "${dashboardUrl}"`, { stdio: 'ignore' });
      else if (process.platform === 'win32')
        execSync(`cmd /c start "" "${dashboardUrl}"`, { stdio: 'ignore' });
      else execSync(`xdg-open "${dashboardUrl}"`, { stdio: 'ignore' });
      // Notify the daemon so it won't open a duplicate tab on the first approval.
      const intToken = getInternalToken();
      fetch(`http://127.0.0.1:${port}/browser-opened`, {
        method: 'POST',
        headers: intToken ? { 'X-Node9-Internal': intToken } : {},
      }).catch(() => {});
    }
  } catch {
    // Browser open failed — URL is printed in the banner below so the user
    // can open it manually.
  }

  // Warn if response-DLP findings exist in audit log
  const auditLog = path.join(os.homedir(), '.node9', 'audit.log');
  try {
    const unackedDlp = fs
      .readFileSync(auditLog, 'utf-8')
      .split('\n')
      .filter((l) => l.includes('"response-dlp"')).length;
    if (unackedDlp > 0) {
      console.log('');
      console.log(
        chalk.bgRed.white.bold(
          ` ⚠️  DLP ALERT: ${unackedDlp} secret${unackedDlp !== 1 ? 's' : ''} found in Claude response text — run: node9 dlp `
        )
      );
    }
  } catch {}

  console.log(chalk.cyan.bold(`\n🛰️  Node9 tail  `) + chalk.dim(`→ ${dashboardUrl}`));
  if (canApprove) {
    console.log(chalk.dim('Card: [↵/y] Allow  [n] Deny  [a] Always  [t] Trust 30m'));
    console.log(chalk.dim(`Approvers (toggle): ${approverStatusLine()}  [q] quit`));
  }
  const ctxStat = readSessionUsage();
  if (ctxStat) console.log('  ' + formatContextStat(ctxStat));
  if (options.history) {
    console.log(chalk.dim('Showing history + live events.\n'));
  } else {
    console.log(chalk.dim('Showing live events only. Use --history to include past.\n'));
  }

  process.on('SIGINT', () => {
    exitIdleMode();
    clearCard();
    process.stdout.write(SHOW_CURSOR);
    if (process.stdout.isTTY) {
      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
    }
    console.log(chalk.dim('\n🛰️  Disconnected.'));
    process.exit(0);
  });

  // Connect with capabilities=input so the daemon knows this is an interactive terminal
  const sseUrl = `http://127.0.0.1:${port}/events?capabilities=input`;
  const req = http.get(sseUrl, (res) => {
    if (res.statusCode !== 200) {
      console.error(chalk.red(`Failed to connect: HTTP ${res.statusCode}`));
      process.exit(1);
    }

    // Start idle keypress listener now that we're connected — avoids terminal
    // artifacts from setRawMode being called before the SSE stream is open.
    if (canApprove) enterIdleMode();

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
      clearCard();
      process.stdout.write(SHOW_CURSOR);
      if (process.stdout.isTTY) {
        readline.clearLine(process.stdout, 0);
        readline.cursorTo(process.stdout, 0);
      }
      console.log(chalk.red('\n❌ Daemon disconnected.'));
      process.exit(1);
    });
  });

  function handleMessage(event: string, rawData: string): void {
    // ── CSRF token ───────────────────────────────────────────────────────────
    if (event === 'csrf') {
      try {
        const parsed = JSON.parse(rawData) as { token: string };
        if (parsed.token) csrfToken = parsed.token;
      } catch {}
      return;
    }

    // ── Initial payload ──────────────────────────────────────────────────────
    if (event === 'init') {
      try {
        const parsed = JSON.parse(rawData) as {
          requests?: ApprovalRequest[];
        };
        // Queue any requests that were pending before we connected
        if (canApprove && Array.isArray(parsed.requests)) {
          for (const r of parsed.requests) {
            approvalQueue.push(r);
          }
          showNextCard();
        }
      } catch {}
      return;
    }

    // ── New approval request ─────────────────────────────────────────────────
    if (event === 'add') {
      if (canApprove) {
        try {
          const parsed = JSON.parse(rawData) as ApprovalRequest & { interactive?: boolean };
          // Only show approval card when terminal approver is enabled in config.
          // browser-only configs still receive 'add' events for the browser UI,
          // but should not render a card in the tail terminal.
          if (parsed.interactive !== false) {
            approvalQueue.push(parsed);
            showNextCard();
          }
        } catch {}
      }
      return;
    }

    // ── Request resolved (by another racer) ──────────────────────────────────
    if (event === 'remove') {
      try {
        const { id, decision } = JSON.parse(rawData) as {
          id: string;
          decision?: 'allow' | 'deny';
        };
        const idx = approvalQueue.findIndex((r) => r.id === id);
        if (idx !== -1) {
          if (idx === 0 && cardActive && cancelActiveCard) {
            // Current card was resolved externally (native popup, browser, timeout).
            // Update local count based on the external decision before cancelling.
            const toolName = approvalQueue[0].toolName;
            if (decision === 'allow') {
              localAllowCounts.set(toolName, (localAllowCounts.get(toolName) ?? 0) + 1);
            } else if (decision === 'deny') {
              localAllowCounts.delete(toolName);
            }
            // cancelActiveCard() stops raw-mode, stamps the card, and advances the queue.
            cancelActiveCard(decision);
          } else {
            approvalQueue.splice(idx, 1);
          }
        }
      } catch {}
      return;
    }

    // ── Activity feed ────────────────────────────────────────────────────────
    let data: ActivityItem & ResultItem;
    try {
      data = JSON.parse(rawData) as ActivityItem & ResultItem;
    } catch {
      return;
    }

    if (event === 'activity') {
      // Ring-buffer replay events (resolved status, old timestamp) are always shown on
      // initial connect so the user sees recent history without needing --history.
      // Once the first live pending event arrives, initialReplayDone = true and the
      // time filter applies normally to avoid re-showing stale events on reconnect.
      const isReplayEvent = data.status && data.status !== 'pending';
      if (isReplayEvent && !initialReplayDone) {
        renderResult(data, data);
        return;
      }

      // History filter: skip old events after initial replay, unless --history requested
      if (!options.history && data.ts > 0 && data.ts < connectionTime) return;

      // Ring-buffer replay: activity events already have a resolved status — render immediately
      if (isReplayEvent) {
        renderResult(data, data);
        return;
      }

      // First live pending event — initial replay is complete
      if (!initialReplayDone) initialReplayDone = true;

      // Race condition: result already arrived before this pending event — render immediately
      const orphaned = orphanedResults.get(data.id);
      if (orphaned) {
        orphanedResults.delete(data.id);
        renderResult(data, orphaned);
        return;
      }

      activityPending.set(data.id, data);
      renderPending(data);
    }

    if (event === 'snapshot') {
      const time = new Date(data.ts).toLocaleTimeString([], { hour12: false });
      const hash = (data as unknown as { hash: string }).hash ?? '';
      const summary = (data as unknown as { argsSummary: string }).argsSummary ?? data.tool;
      const fileCount = (data as unknown as { fileCount: number }).fileCount ?? 0;
      const files =
        fileCount > 0 ? chalk.dim(` · ${fileCount} file${fileCount === 1 ? '' : 's'}`) : '';
      process.stdout.write(
        `${chalk.dim(time)}  ${chalk.cyan('📸 snapshot')}  ${chalk.dim(hash)}  ${summary}${files}\n`
      );
      return;
    }

    if (event === 'activity-result') {
      const original = activityPending.get(data.id);
      if (original) {
        renderResult(original, data);
        activityPending.delete(data.id);
      } else {
        // Race condition: result arrived before pending — buffer it until activity arrives
        orphanedResults.set(data.id, data);
      }
    }

    if (event === 'execution-result') {
      // Emitted by the MCP gateway when an upstream tool call returns. Renders
      // as a small follow-up line under the auth row so the user sees both the
      // authorization decision (already on screen) and the actual completion.
      const exec = data as unknown as {
        tool?: string;
        agent?: string;
        mcpServer?: string;
        durationMs?: number;
        isError?: boolean;
      };
      const time = new Date(Date.now()).toLocaleTimeString([], { hour12: false });
      const arrow = exec.isError ? chalk.red('  ↳ ✗') : chalk.green('  ↳ ✓');
      const label = agentLabel(exec.agent, exec.mcpServer);
      const tool = (exec.tool ?? '').slice(0, 16);
      const duration =
        typeof exec.durationMs === 'number' ? chalk.dim(` (${exec.durationMs}ms)`) : '';
      console.log(
        `${chalk.gray(time)} ${arrow} ${label}${chalk.dim(tool)}${chalk.dim(' completed')}${duration}`
      );
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
