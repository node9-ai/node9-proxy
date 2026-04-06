// src/cli/hud.ts
// node9 HUD subprocess — spawned by Claude Code's statusLine every ~300ms.
// Reads session JSON from stdin, queries the daemon for security state,
// renders up to three ANSI lines to stdout.
//
// Architecture: stateless re-spawn (not persistent). Claude Code writes
// JSON to stdin and closes it; we read until EOF, then render and exit.

import fs from 'fs';
import path from 'path';
import os from 'os';
import http from 'http';
import { DAEMON_PORT, DAEMON_HOST } from '../auth/daemon.js';
import type { HudStatus } from '../daemon/session-counters.js';

// ── stdin JSON from Claude Code ───────────────────────────────────────────────

interface RateLimitWindow {
  used_percentage?: number;
  resets_at?: string;
}

interface ClaudeStdinData {
  model?: { display_name?: string } | string;
  context_window?: {
    current_usage?: { input_tokens?: number; output_tokens?: number; cache_read_tokens?: number };
    context_window_size?: number;
    used_percentage?: number;
  };
  transcript_path?: string;
  cwd?: string;
  rate_limits?: {
    five_hour?: RateLimitWindow;
    seven_day?: RateLimitWindow;
  };
}

async function readStdin(): Promise<ClaudeStdinData> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString('utf-8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw) as ClaudeStdinData;
  } catch {
    return {};
  }
}

// ── Daemon query ──────────────────────────────────────────────────────────────

function queryDaemon(): Promise<HudStatus | null> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 50);
    try {
      const req = http.get(
        `http://${DAEMON_HOST}:${DAEMON_PORT}/status`,
        { timeout: 50 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            clearTimeout(timeout);
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString()) as HudStatus);
            } catch {
              resolve(null);
            }
          });
        }
      );
      req.on('error', () => {
        clearTimeout(timeout);
        resolve(null);
      });
      req.on('timeout', () => {
        clearTimeout(timeout);
        req.destroy();
        resolve(null);
      });
    } catch {
      clearTimeout(timeout);
      resolve(null);
    }
  });
}

// ── ANSI helpers ──────────────────────────────────────────────────────────────

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const MAGENTA = '\x1b[35m';
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';
function dim(s: string): string {
  return `${DIM}${s}${RESET}`;
}
function bold(s: string): string {
  return `${BOLD}${s}${RESET}`;
}
function color(c: string, s: string): string {
  return `${c}${s}${RESET}`;
}

// ── Progress bar ──────────────────────────────────────────────────────────────

const BAR_FILLED = '█';
const BAR_EMPTY = '░';
const BAR_WIDTH = 10;

function progressBar(pct: number, warnAt = 70, critAt = 85): string {
  const filled = Math.round((Math.min(pct, 100) / 100) * BAR_WIDTH);
  const bar = BAR_FILLED.repeat(filled) + BAR_EMPTY.repeat(BAR_WIDTH - filled);
  const c = pct >= critAt ? RED : pct >= warnAt ? YELLOW : GREEN;
  return `${c}${bar}${RESET}`;
}

// ── Duration formatting ───────────────────────────────────────────────────────

function formatTimeLeft(resetsAt: string | undefined): string {
  if (!resetsAt) return '';
  const ms = new Date(resetsAt).getTime() - Date.now();
  if (ms <= 0) return '';
  const totalMin = Math.ceil(ms / 60_000);
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h > 0) return ` (${h}h ${m}m left)`;
  return ` (${m}m left)`;
}

// ── Environment counts (CLAUDE.md / rules / MCPs / hooks) ────────────────────

interface EnvCounts {
  claudeMdCount: number;
  rulesCount: number;
  mcpCount: number;
  hooksCount: number;
}

function safeReadJson(filePath: string): Record<string, unknown> | null {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function getMcpServerNames(filePath: string): Set<string> {
  const cfg = safeReadJson(filePath);
  if (!cfg || typeof cfg.mcpServers !== 'object' || cfg.mcpServers === null) return new Set();
  return new Set(Object.keys(cfg.mcpServers as object));
}

function getDisabledMcpServers(
  filePath: string,
  key: 'disabledMcpServers' | 'disabledMcpjsonServers'
): Set<string> {
  const cfg = safeReadJson(filePath);
  if (!cfg || !Array.isArray(cfg[key])) return new Set();
  return new Set((cfg[key] as unknown[]).filter((s): s is string => typeof s === 'string'));
}

function countHooksInFile(filePath: string): number {
  const cfg = safeReadJson(filePath);
  if (!cfg || typeof cfg.hooks !== 'object' || cfg.hooks === null) return 0;
  return Object.keys(cfg.hooks).length;
}

function countRulesInDir(rulesDir: string): number {
  if (!fs.existsSync(rulesDir)) return 0;
  let count = 0;
  try {
    for (const entry of fs.readdirSync(rulesDir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        count += countRulesInDir(path.join(rulesDir, entry.name));
      } else if (entry.isFile() && entry.name.endsWith('.md')) {
        count++;
      }
    }
  } catch {
    // unreadable directory — skip
  }
  return count;
}

function isSamePath(a: string, b: string): boolean {
  try {
    return path.resolve(a) === path.resolve(b);
  } catch {
    return false;
  }
}

export function countConfigs(cwd?: string): EnvCounts {
  const homeDir = os.homedir();
  const claudeDir = path.join(homeDir, '.claude');

  let claudeMdCount = 0;
  let rulesCount = 0;
  let hooksCount = 0;

  const userMcpServers = new Set<string>();
  const projectMcpServers = new Set<string>();

  // ── User scope ──────────────────────────────────────────────────────────────

  if (fs.existsSync(path.join(claudeDir, 'CLAUDE.md'))) claudeMdCount++;
  rulesCount += countRulesInDir(path.join(claudeDir, 'rules'));

  const userSettings = path.join(claudeDir, 'settings.json');
  for (const name of getMcpServerNames(userSettings)) userMcpServers.add(name);
  hooksCount += countHooksInFile(userSettings);

  // ~/.claude.json (additional user-scope MCPs)
  const userClaudeJson = path.join(homeDir, '.claude.json');
  for (const name of getMcpServerNames(userClaudeJson)) userMcpServers.add(name);
  for (const name of getDisabledMcpServers(userClaudeJson, 'disabledMcpServers')) {
    userMcpServers.delete(name);
  }

  // ── Project scope ───────────────────────────────────────────────────────────

  if (cwd) {
    // CLAUDE.md variants in project root
    if (fs.existsSync(path.join(cwd, 'CLAUDE.md'))) claudeMdCount++;
    if (fs.existsSync(path.join(cwd, 'CLAUDE.local.md'))) claudeMdCount++;

    const projectClaudeDir = path.join(cwd, '.claude');
    const overlapsUserScope = isSamePath(projectClaudeDir, claudeDir);

    if (!overlapsUserScope) {
      if (fs.existsSync(path.join(projectClaudeDir, 'CLAUDE.md'))) claudeMdCount++;
      rulesCount += countRulesInDir(path.join(projectClaudeDir, 'rules'));
      const projSettings = path.join(projectClaudeDir, 'settings.json');
      for (const name of getMcpServerNames(projSettings)) projectMcpServers.add(name);
      hooksCount += countHooksInFile(projSettings);
    }

    if (fs.existsSync(path.join(projectClaudeDir, 'CLAUDE.local.md'))) claudeMdCount++;

    // {cwd}/.claude/settings.local.json
    const localSettings = path.join(projectClaudeDir, 'settings.local.json');
    for (const name of getMcpServerNames(localSettings)) projectMcpServers.add(name);
    hooksCount += countHooksInFile(localSettings);

    // {cwd}/.mcp.json
    const mcpJsonServers = getMcpServerNames(path.join(cwd, '.mcp.json'));
    const disabledMcpJson = getDisabledMcpServers(localSettings, 'disabledMcpjsonServers');
    for (const name of disabledMcpJson) mcpJsonServers.delete(name);
    for (const name of mcpJsonServers) projectMcpServers.add(name);
  }

  return {
    claudeMdCount,
    rulesCount,
    mcpCount: userMcpServers.size + projectMcpServers.size,
    hooksCount,
  };
}

export function renderEnvironmentLine(counts: EnvCounts): string | null {
  const { claudeMdCount, rulesCount, mcpCount, hooksCount } = counts;
  if (claudeMdCount === 0 && rulesCount === 0 && mcpCount === 0 && hooksCount === 0) return null;

  const parts = [
    `${claudeMdCount} CLAUDE.md`,
    `${rulesCount} rules`,
    `${mcpCount} MCPs`,
    `${hooksCount} hooks`,
  ];

  return color(DIM, parts.join(` ${dim('|')} `));
}

// ── HUD line rendering ────────────────────────────────────────────────────────

function renderOffline(): void {
  process.stdout.write(`${color(BLUE, '🛡')} ${bold('node9')} ${dim('|')} ${dim('offline')}\n`);
}

function readActiveShieldsHud(): string[] {
  try {
    const shieldsPath = path.join(os.homedir(), '.node9', 'shields.json');
    if (!fs.existsSync(shieldsPath)) return [];
    const parsed = JSON.parse(fs.readFileSync(shieldsPath, 'utf-8')) as { active?: unknown };
    if (!Array.isArray(parsed.active)) return [];
    return (parsed.active as unknown[]).filter((s): s is string => typeof s === 'string');
  } catch {
    return [];
  }
}

function renderSecurityLine(status: HudStatus): string {
  const parts: string[] = [];

  // Shield icon + node9 brand
  parts.push(`${color(BLUE, '🛡')} ${bold('node9')}`);

  // Mode indicator
  const modeColors: Record<string, string> = {
    standard: GREEN,
    strict: RED,
    observe: MAGENTA,
    audit: YELLOW,
  };
  const modeIcon: Record<string, string> = {
    standard: '',
    strict: '',
    observe: '👁 ',
    audit: '',
  };
  const mc = modeColors[status.mode] ?? WHITE;
  parts.push(`${dim('|')} ${color(mc, modeIcon[status.mode] ?? '')}${color(mc, status.mode)}`);

  // Active shields
  const activeShields = readActiveShieldsHud();
  if (activeShields.length > 0) {
    const shieldAbbrevs: Record<string, string> = {
      'bash-safe': 'bash',
      filesystem: 'fs',
      postgres: 'pg',
      github: 'gh',
      aws: 'aws',
    };
    const labels = activeShields.map((s) => shieldAbbrevs[s] ?? s).join(' ');
    parts.push(color(DIM, `[${labels}]`));
  }

  // Session counters
  if (status.mode === 'observe') {
    parts.push(`${dim('|')} ${color(GREEN, `✅ ${status.session.allowed} passed`)}`);
    if (status.session.wouldBlock > 0) {
      parts.push(color(YELLOW, `⚠ ${status.session.wouldBlock} would-block`));
    }
  } else {
    parts.push(`${dim('|')} ${color(GREEN, `✅ ${status.session.allowed} allowed`)}`);
    if (status.session.blocked > 0) {
      parts.push(color(RED, `🛑 ${status.session.blocked} blocked`));
    }
    if (status.session.dlpHits > 0) {
      parts.push(color(RED, `🚨 ${status.session.dlpHits} dlp`));
    }
  }

  // Session cost estimate
  if (status.session.estimatedCost > 0) {
    const cost = status.session.estimatedCost;
    const costStr =
      cost >= 0.01 ? `$${cost.toFixed(2)}` : cost >= 0.001 ? `$${cost.toFixed(3)}` : '<$0.001';
    parts.push(color(DIM, `~${costStr}`));
  }

  // Taint count
  if (status.taintedCount > 0) {
    parts.push(color(YELLOW, `💧 ${status.taintedCount} tainted`));
  }

  // Last rule hit
  if (status.lastRuleHit) {
    const ruleName = status.lastRuleHit.replace(/^Smart Rule:\s*/i, '');
    parts.push(color(CYAN, `⚡ ${ruleName}`));
  }

  return parts.join('  ');
}

function renderContextLine(stdin: ClaudeStdinData): string | null {
  const cw = stdin.context_window;
  if (!cw) return null;

  const parts: string[] = [];

  // Model name
  const modelName =
    typeof stdin.model === 'string' ? stdin.model : (stdin.model?.display_name ?? '');
  if (modelName) {
    parts.push(color(CYAN, modelName));
  }

  // Context bar
  const usedPct =
    cw.used_percentage ??
    (cw.current_usage && cw.context_window_size
      ? Math.round(
          (((cw.current_usage.input_tokens ?? 0) + (cw.current_usage.output_tokens ?? 0)) /
            cw.context_window_size) *
            100
        )
      : null);

  if (usedPct !== null) {
    const bar = progressBar(usedPct);
    parts.push(`${dim('│')} ctx ${bar} ${usedPct}%`);
  }

  // Rate limits
  const rl = stdin.rate_limits;
  if (rl?.five_hour?.used_percentage !== undefined) {
    const pct = Math.round(rl.five_hour.used_percentage);
    const bar = progressBar(pct, 60, 80);
    const left = formatTimeLeft(rl.five_hour.resets_at);
    parts.push(`${dim('│')} 5h ${bar} ${pct}%${left}`);
  }
  if (rl?.seven_day?.used_percentage !== undefined) {
    const pct = Math.round(rl.seven_day.used_percentage);
    const bar = progressBar(pct, 60, 80);
    parts.push(`${dim('│')} 7d ${bar} ${pct}%`);
  }

  if (parts.length === 0) return null;
  return parts.join('  ');
}

// ── Main ──────────────────────────────────────────────────────────────────────

export async function main(): Promise<void> {
  try {
    const [stdin, daemonStatus] = await Promise.all([readStdin(), queryDaemon()]);

    if (!daemonStatus) {
      renderOffline();
      return;
    }

    // Line 1: security state
    process.stdout.write(renderSecurityLine(daemonStatus) + '\n');

    // Line 2: context + rate limits (if data available)
    const ctxLine = renderContextLine(stdin);
    if (ctxLine) {
      process.stdout.write(ctxLine + '\n');
    }

    // Line 3: environment counts — CLAUDE.md / rules / MCPs / hooks
    // Controlled by settings.hud.showEnvironmentCounts (default: true).
    // Read directly from config files to avoid pulling getConfig into the module
    // graph (which breaks the http mock in hud tests).
    const showEnvCounts = (() => {
      try {
        const cwd = stdin.cwd ?? process.cwd();
        for (const configPath of [
          path.join(cwd, 'node9.config.json'),
          path.join(os.homedir(), '.node9', 'config.json'),
        ]) {
          if (!fs.existsSync(configPath)) continue;
          const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
          const hud = (cfg.settings as Record<string, unknown> | undefined)?.hud as
            | Record<string, unknown>
            | undefined;
          if (hud && 'showEnvironmentCounts' in hud) return hud.showEnvironmentCounts !== false;
        }
      } catch {
        /* ignore */
      }
      return true; // default: show
    })();
    if (showEnvCounts) {
      const envLine = renderEnvironmentLine(countConfigs(stdin.cwd));
      if (envLine) {
        process.stdout.write(envLine + '\n');
      }
    }
  } catch {
    // Fail-open: if anything throws, render offline indicator
    renderOffline();
  }
}
