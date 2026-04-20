// src/cli/commands/scan.ts
// Registered as `node9 scan` by cli.ts.
//
// Forecast: reads Claude JSONL history and shows what node9 would catch
// if installed. Uses the real policy engine (shields + user rules + cloud rules)
// so results are identical to live enforcement.
//
// Distinct from `node9 report`:
//   report = ongoing monitoring using audit.log (needs node9 running)
//   scan   = day-0 forecast from raw agent history (no audit.log needed)

import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { SHIELDS } from '../../shields';
import { getConfig, DEFAULT_CONFIG } from '../../config';
import {
  evaluateSmartConditions,
  matchesPattern,
  detectDangerousShellExec,
} from '../../policy/index';
import { scanArgs } from '../../dlp';
import type { SmartRule } from '../../core';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type RuleSourceType = 'default' | 'shield' | 'user';

interface RuleSource {
  shieldName: string;
  shieldLabel: string;
  sourceType: RuleSourceType;
  rule: SmartRule;
}

interface Finding {
  source: RuleSource;
  toolName: string;
  input: Record<string, unknown>;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: 'claude' | 'gemini';
}

interface DlpFinding {
  patternName: string;
  redactedSample: string;
  toolName: string;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: 'claude' | 'gemini';
}

interface JournalEntry {
  type: string;
  timestamp?: string;
  message?: {
    model?: string;
    content?: Array<{ type: string; name?: string; input?: Record<string, unknown> }>;
    usage?: {
      input_tokens?: number;
      output_tokens?: number;
      cache_creation_input_tokens?: number;
      cache_read_input_tokens?: number;
    };
  };
}

interface ScanResult {
  filesScanned: number;
  sessions: number;
  totalToolCalls: number;
  bashCalls: number;
  findings: Finding[];
  dlpFindings: DlpFinding[];
  totalCostUSD: number;
  firstDate: string | null;
  lastDate: string | null;
}

// ---------------------------------------------------------------------------
// Pricing (for all-time cost summary)
// ---------------------------------------------------------------------------

const CLAUDE_PRICING: Record<string, { i: number; o: number; cw: number; cr: number }> = {
  'claude-opus-4-6': { i: 5e-6, o: 25e-6, cw: 6.25e-6, cr: 0.5e-6 },
  'claude-opus-4-5': { i: 5e-6, o: 25e-6, cw: 6.25e-6, cr: 0.5e-6 },
  'claude-opus-4': { i: 15e-6, o: 75e-6, cw: 18.75e-6, cr: 1.5e-6 },
  'claude-sonnet-4-6': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-sonnet-4-5': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-sonnet-4': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-3-7-sonnet': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-3-5-sonnet': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-haiku-4-5': { i: 1e-6, o: 5e-6, cw: 1.25e-6, cr: 0.1e-6 },
  'claude-3-5-haiku': { i: 0.8e-6, o: 4e-6, cw: 1e-6, cr: 0.08e-6 },
};

function claudeModelPrice(model: string): { i: number; o: number; cw: number; cr: number } | null {
  const base = model.replace(/@.*$/, '').replace(/-\d{8}$/, '');
  for (const [key, p] of Object.entries(CLAUDE_PRICING)) {
    if (base === key || base.startsWith(key)) return p;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Gemini pricing
// ---------------------------------------------------------------------------

const GEMINI_PRICING: Record<string, { i: number; o: number; cr: number }> = {
  'gemini-2.5-pro': { i: 1.25e-6, o: 10e-6, cr: 0.31e-6 },
  'gemini-2.5-flash': { i: 0.15e-6, o: 0.6e-6, cr: 0.0375e-6 },
  'gemini-2.0-flash': { i: 0.1e-6, o: 0.4e-6, cr: 0.025e-6 },
  'gemini-1.5-pro': { i: 1.25e-6, o: 5e-6, cr: 0.3125e-6 },
  'gemini-1.5-flash': { i: 0.075e-6, o: 0.3e-6, cr: 0.01875e-6 },
  'gemini-3-flash': { i: 0.1e-6, o: 0.4e-6, cr: 0.025e-6 },
};

function geminiModelPrice(model: string): { i: number; o: number; cr: number } | null {
  const base = model
    .replace(/-preview$/, '')
    .replace(/-exp$/, '')
    .replace(/-\d{4}-\d{2}-\d{2}$/, '');
  for (const [key, p] of Object.entries(GEMINI_PRICING)) {
    if (base === key || base.startsWith(key)) return p;
  }
  if (base.includes('flash')) return GEMINI_PRICING['gemini-2.0-flash']!;
  return null;
}

// ---------------------------------------------------------------------------
// Gemini session types
// ---------------------------------------------------------------------------

interface GeminiSessionFile {
  sessionId?: string;
  startTime?: string;
  messages?: Array<{
    type: string;
    timestamp?: string;
    tokens?: { input: number; output: number; cached: number };
    model?: string;
    toolCalls?: Array<{ name?: string; args?: Record<string, unknown> }>;
    content?: Array<{ text?: string }> | string;
  }>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function num(n: number): string {
  return n.toLocaleString();
}

function fmtCost(usd: number): string {
  if (usd < 0.001) return '< $0.001';
  if (usd < 1) return '$' + usd.toFixed(4);
  return '$' + usd.toFixed(2);
}

function fmtTs(ts: string): string {
  try {
    return new Date(ts).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return ts.slice(0, 10);
  }
}

function preview(input: Record<string, unknown>, max: number): string {
  const cmd = input.command ?? input.query ?? input.file_path ?? JSON.stringify(input);
  const s = String(cmd).replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function fullCommand(input: Record<string, unknown>): string {
  const cmd = input.command ?? input.query ?? input.file_path ?? JSON.stringify(input);
  return String(cmd).replace(/\s+/g, ' ').trim();
}

// ---------------------------------------------------------------------------
// Build the rule set for scan
// ---------------------------------------------------------------------------

const DEFAULT_RULE_NAMES = new Set(
  DEFAULT_CONFIG.policy.smartRules.map((r) => r.name).filter(Boolean)
);

function buildRuleSources(): RuleSource[] {
  const sources: RuleSource[] = [];

  // 1. All shields (builtin + user-installed)
  for (const [shieldName, shield] of Object.entries(SHIELDS)) {
    for (const rule of shield.smartRules) {
      sources.push({ shieldName, shieldLabel: shieldName, sourceType: 'shield', rule });
    }
  }

  // 2. Default built-in rules + user custom rules + cloud rules
  try {
    const config = getConfig();
    for (const rule of config.policy.smartRules) {
      if (!rule.name) continue;
      if (rule.name.startsWith('shield:')) continue;
      const isCloud = rule.name.startsWith('cloud:');
      const isDefault = DEFAULT_RULE_NAMES.has(rule.name);
      const sourceType: RuleSourceType = isCloud ? 'user' : isDefault ? 'default' : 'user';
      sources.push({
        shieldName: isCloud ? 'cloud' : isDefault ? 'default' : 'custom',
        shieldLabel: isCloud ? 'Cloud Policy' : isDefault ? 'Default Rules' : 'Your Rules',
        sourceType,
        rule,
      });
    }
  } catch {
    // getConfig() may fail on a truly fresh install — skip user rules silently
  }

  return sources;
}

// ---------------------------------------------------------------------------
// JSONL scanner
// ---------------------------------------------------------------------------

function scanClaudeHistory(startDate: Date | null): ScanResult {
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');

  const result: ScanResult = {
    filesScanned: 0,
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    findings: [],
    dlpFindings: [],
    totalCostUSD: 0,
    firstDate: null,
    lastDate: null,
  };

  if (!fs.existsSync(projectsDir)) return result;

  let projDirs: string[];
  try {
    projDirs = fs.readdirSync(projectsDir);
  } catch {
    return result;
  }

  const ruleSources = buildRuleSources();

  for (const proj of projDirs) {
    const projPath = path.join(projectsDir, proj);
    try {
      if (!fs.statSync(projPath).isDirectory()) continue;
    } catch {
      continue;
    }

    const projLabel = decodeURIComponent(proj).replace(os.homedir(), '~').slice(0, 40);

    let files: string[];
    try {
      files = fs
        .readdirSync(projPath)
        .filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-'));
    } catch {
      continue;
    }

    for (const file of files) {
      result.filesScanned++;
      result.sessions++;

      const sessionId = file.replace(/\.jsonl$/, '');

      let raw: string;
      try {
        raw = fs.readFileSync(path.join(projPath, file), 'utf-8');
      } catch {
        continue;
      }

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;

        let entry: JournalEntry;
        try {
          entry = JSON.parse(line) as JournalEntry;
        } catch {
          continue;
        }

        if (entry.type !== 'assistant') continue;

        // Date filter
        if (startDate && entry.timestamp) {
          if (new Date(entry.timestamp) < startDate) continue;
        }

        // Track date range
        if (entry.timestamp) {
          if (!result.firstDate || entry.timestamp < result.firstDate)
            result.firstDate = entry.timestamp;
          if (!result.lastDate || entry.timestamp > result.lastDate)
            result.lastDate = entry.timestamp;
        }

        // Cost
        const usage = entry.message?.usage;
        const model = entry.message?.model;
        if (usage && model) {
          const p = claudeModelPrice(model);
          if (p) {
            result.totalCostUSD +=
              (usage.input_tokens ?? 0) * p.i +
              (usage.output_tokens ?? 0) * p.o +
              (usage.cache_creation_input_tokens ?? 0) * p.cw +
              (usage.cache_read_input_tokens ?? 0) * p.cr;
          }
        }

        // Tool calls
        const content = entry.message?.content;
        if (!Array.isArray(content)) continue;

        for (const block of content) {
          if (block.type !== 'tool_use') continue;
          result.totalToolCalls++;

          const toolName = block.name ?? '';
          const toolNameLower = toolName.toLowerCase();
          const input = block.input ?? {};

          if (toolNameLower === 'bash' || toolNameLower === 'execute_bash') {
            result.bashCalls++;
          }

          // Skip node9's own read-only CLI calls
          const rawCmd = String(input.command ?? '').trimStart();
          if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd))
            continue;

          // ── DLP scan ───────────────────────────────────────────────────
          const dlpMatch = scanArgs(input);
          if (dlpMatch) {
            const isDupe = result.dlpFindings.some(
              (f) =>
                f.patternName === dlpMatch.patternName &&
                f.redactedSample === dlpMatch.redactedSample &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.dlpFindings.push({
                patternName: dlpMatch.patternName,
                redactedSample: dlpMatch.redactedSample,
                toolName,
                timestamp: entry.timestamp ?? '',
                project: projLabel,
                sessionId,
                agent: 'claude',
              });
            }
          }

          // ── Smart rule matching ────────────────────────────────────────
          let ruleMatched = false;
          for (const source of ruleSources) {
            const { rule } = source;

            if (rule.verdict === 'allow') continue;
            if (rule.tool && !matchesPattern(toolNameLower, rule.tool)) continue;
            if (!evaluateSmartConditions(input, rule)) continue;

            const inputPreview = preview(input, 120);
            const isDupe = result.findings.some(
              (f) =>
                f.source.rule.name === rule.name &&
                preview(f.input, 120) === inputPreview &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.findings.push({
                source,
                toolName,
                input,
                timestamp: entry.timestamp ?? '',
                project: projLabel,
                sessionId,
                agent: 'claude',
              });
            }

            ruleMatched = true;
            break; // First matching rule wins per tool call
          }

          // ── AST shell exec detection (catches eval/bash -c with remote download)
          if (!ruleMatched && (toolNameLower === 'bash' || toolNameLower === 'execute_bash')) {
            const shellVerdict = detectDangerousShellExec(String(input.command ?? ''));
            if (shellVerdict) {
              const astRule: SmartRule = {
                name: `ast:bash-safe:${shellVerdict}-shell-exec-remote`,
                tool: 'bash',
                conditions: [],
                verdict: shellVerdict,
                reason: `Shell execution of remote download detected by AST analysis (bash-safe)`,
              };
              const inputPreview = preview(input, 120);
              const isDupe = result.findings.some(
                (f) =>
                  f.source.rule.name === astRule.name &&
                  preview(f.input, 120) === inputPreview &&
                  f.project === projLabel
              );
              if (!isDupe) {
                result.findings.push({
                  source: {
                    shieldName: 'bash-safe',
                    shieldLabel: 'bash-safe (AST)',
                    sourceType: 'shield',
                    rule: astRule,
                  },
                  toolName,
                  input,
                  timestamp: entry.timestamp ?? '',
                  project: projLabel,
                  sessionId,
                  agent: 'claude',
                });
              }
            }
          }
        }
      }
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Gemini history scanner
// ---------------------------------------------------------------------------

function scanGeminiHistory(startDate: Date | null): ScanResult {
  const tmpDir = path.join(os.homedir(), '.gemini', 'tmp');
  const result: ScanResult = {
    filesScanned: 0,
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    findings: [],
    dlpFindings: [],
    totalCostUSD: 0,
    firstDate: null,
    lastDate: null,
  };

  if (!fs.existsSync(tmpDir)) return result;

  let slugDirs: string[];
  try {
    slugDirs = fs.readdirSync(tmpDir);
  } catch {
    return result;
  }

  const ruleSources = buildRuleSources();

  for (const slug of slugDirs) {
    const slugPath = path.join(tmpDir, slug);
    try {
      if (!fs.statSync(slugPath).isDirectory()) continue;
    } catch {
      continue;
    }

    let projLabel = slug;
    try {
      projLabel = fs
        .readFileSync(path.join(slugPath, '.project_root'), 'utf-8')
        .trim()
        .replace(os.homedir(), '~')
        .slice(0, 40);
    } catch {}

    const chatsDir = path.join(slugPath, 'chats');
    if (!fs.existsSync(chatsDir)) continue;

    let chatFiles: string[];
    try {
      chatFiles = fs.readdirSync(chatsDir).filter((f) => f.endsWith('.json'));
    } catch {
      continue;
    }

    for (const chatFile of chatFiles) {
      result.filesScanned++;

      const sessionId = chatFile.replace(/\.json$/, '');

      let raw: string;
      try {
        raw = fs.readFileSync(path.join(chatsDir, chatFile), 'utf-8');
      } catch {
        continue;
      }

      let session: GeminiSessionFile;
      try {
        session = JSON.parse(raw) as GeminiSessionFile;
      } catch {
        continue;
      }

      result.sessions++;

      for (const msg of session.messages ?? []) {
        if (msg.type !== 'gemini') continue;

        if (startDate && msg.timestamp && new Date(msg.timestamp) < startDate) continue;

        if (msg.timestamp) {
          if (!result.firstDate || msg.timestamp < result.firstDate)
            result.firstDate = msg.timestamp;
          if (!result.lastDate || msg.timestamp > result.lastDate) result.lastDate = msg.timestamp;
        }

        const tokens = msg.tokens;
        const model = msg.model;
        if (tokens && model) {
          const p = geminiModelPrice(model);
          if (p) {
            const nonCached = Math.max(0, tokens.input - tokens.cached);
            result.totalCostUSD += nonCached * p.i + tokens.cached * p.cr + tokens.output * p.o;
          }
        }

        for (const tc of msg.toolCalls ?? []) {
          result.totalToolCalls++;
          const toolName = tc.name ?? '';
          const toolNameLower = toolName.toLowerCase();
          const input = tc.args ?? {};

          if (toolNameLower === 'run_shell_command' || toolNameLower === 'shell') {
            result.bashCalls++;
          }

          const rawCmd = String(input.command ?? '').trimStart();
          if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd))
            continue;

          const dlpMatch = scanArgs(input);
          if (dlpMatch) {
            const isDupe = result.dlpFindings.some(
              (f) =>
                f.patternName === dlpMatch.patternName &&
                f.redactedSample === dlpMatch.redactedSample &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.dlpFindings.push({
                patternName: dlpMatch.patternName,
                redactedSample: dlpMatch.redactedSample,
                toolName,
                timestamp: msg.timestamp ?? '',
                project: projLabel,
                sessionId,
                agent: 'gemini',
              });
            }
          }

          let ruleMatched = false;
          for (const source of ruleSources) {
            const { rule } = source;
            if (rule.verdict === 'allow') continue;
            if (rule.tool && !matchesPattern(toolNameLower, rule.tool)) continue;
            if (!evaluateSmartConditions(input, rule)) continue;

            const inputPreview = preview(input, 120);
            const isDupe = result.findings.some(
              (f) =>
                f.source.rule.name === rule.name &&
                preview(f.input, 120) === inputPreview &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.findings.push({
                source,
                toolName,
                input,
                timestamp: msg.timestamp ?? '',
                project: projLabel,
                sessionId,
                agent: 'gemini',
              });
            }
            ruleMatched = true;
            break;
          }

          // ── AST shell exec detection (catches eval/bash -c with remote download)
          const isShellTool = ['bash', 'execute_bash', 'run_shell_command', 'shell'].includes(
            toolNameLower
          );
          if (!ruleMatched && isShellTool) {
            const shellVerdict = detectDangerousShellExec(String(input.command ?? ''));
            if (shellVerdict) {
              const astRule: SmartRule = {
                name: `ast:bash-safe:${shellVerdict}-shell-exec-remote`,
                tool: 'bash',
                conditions: [],
                verdict: shellVerdict,
                reason: `Shell execution of remote download detected by AST analysis (bash-safe)`,
              };
              const inputPreview = preview(input, 120);
              const isDupe = result.findings.some(
                (f) =>
                  f.source.rule.name === astRule.name &&
                  preview(f.input, 120) === inputPreview &&
                  f.project === projLabel
              );
              if (!isDupe) {
                result.findings.push({
                  source: {
                    shieldName: 'bash-safe',
                    shieldLabel: 'bash-safe (AST)',
                    sourceType: 'shield',
                    rule: astRule,
                  },
                  toolName,
                  input,
                  timestamp: msg.timestamp ?? '',
                  project: projLabel,
                  sessionId,
                  agent: 'gemini',
                });
              }
            }
          }
        }
      }
    }
  }

  return result;
}

function mergeScans(a: ScanResult, b: ScanResult): ScanResult {
  const dates = [a.firstDate, b.firstDate].filter(Boolean) as string[];
  const lastDates = [a.lastDate, b.lastDate].filter(Boolean) as string[];
  return {
    filesScanned: a.filesScanned + b.filesScanned,
    sessions: a.sessions + b.sessions,
    totalToolCalls: a.totalToolCalls + b.totalToolCalls,
    bashCalls: a.bashCalls + b.bashCalls,
    findings: [...a.findings, ...b.findings],
    dlpFindings: [...a.dlpFindings, ...b.dlpFindings],
    totalCostUSD: a.totalCostUSD + b.totalCostUSD,
    firstDate: dates.length ? dates.sort()[0] : null,
    lastDate: lastDates.length ? lastDates.sort().at(-1)! : null,
  };
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

function verdictIcon(verdict: string): string {
  return verdict === 'block' ? '🛑' : '👁 ';
}

function printFindingRow(
  f: Finding,
  drillDown: boolean,
  showSessionId: boolean,
  previewWidth: number
): void {
  const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
  const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
  const agentBadge = f.agent === 'gemini' ? chalk.blue('[Gemini]  ') : chalk.cyan('[Claude]  ');
  const cmd = drillDown
    ? chalk.gray(fullCommand(f.input))
    : chalk.gray(preview(f.input, previewWidth));
  const sessionSuffix =
    showSessionId && f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
  console.log(`      ${ts}${proj}${agentBadge}${cmd}${sessionSuffix}`);
}

function printRuleGroup(
  ruleFindings: Finding[],
  topN: number,
  drillDown: boolean,
  previewWidth: number
): void {
  const rule = ruleFindings[0].source.rule;
  const ruleCount = ruleFindings.length;
  const countBadge = ruleCount > 1 ? chalk.white(` ×${ruleCount}`) : '';
  const shortName = (rule.name ?? 'unnamed').replace(/^shield:[^:]+:/, '');
  const icon = verdictIcon(rule.verdict ?? 'review');
  console.log(
    '    ' +
      icon +
      '  ' +
      chalk.white(shortName) +
      countBadge +
      (rule.reason ? chalk.dim(`  — ${rule.reason}`) : '')
  );

  const shown = drillDown ? ruleFindings : ruleFindings.slice(0, topN);
  for (const f of shown) {
    printFindingRow(f, drillDown, drillDown, previewWidth);
  }
  if (!drillDown && ruleFindings.length > topN) {
    console.log(
      chalk.dim(`      … and ${ruleFindings.length - topN} more  (--drill-down for full list)`)
    );
  }
}

// ---------------------------------------------------------------------------
// Registered command
// ---------------------------------------------------------------------------

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Forecast: scan agent history and show what node9 would catch if installed')
    .option('--all', 'Scan all history (default: last 90 days)')
    .option('--days <n>', 'Scan last N days of history', '90')
    .option('--top <n>', 'Max findings to show per rule (default: 5)', '5')
    .option('--drill-down', 'Show all findings with full commands and session IDs')
    .action((options: { all?: boolean; days: string; top: string; drillDown?: boolean }) => {
      const drillDown = options.drillDown ?? false;
      const topN = drillDown ? Infinity : Math.max(1, parseInt(options.top, 10) || 5);
      const previewWidth = 70;
      const startDate = options.all
        ? null
        : (() => {
            const d = new Date();
            d.setDate(d.getDate() - (parseInt(options.days, 10) || 90));
            d.setHours(0, 0, 0, 0);
            return d;
          })();

      console.log('');
      console.log(chalk.cyan.bold('🔍  node9 scan') + chalk.dim('  — what would node9 catch?'));
      console.log('');

      process.stdout.write(chalk.dim('  Scanning…'));
      const claudeScan = scanClaudeHistory(startDate);
      const geminiScan = scanGeminiHistory(startDate);
      const scan = mergeScans(claudeScan, geminiScan);
      process.stdout.write('\r' + ' '.repeat(20) + '\r');

      if (scan.filesScanned === 0) {
        console.log(chalk.yellow('  No session history found.'));
        console.log(
          chalk.gray(
            '  Supported: Claude Code (~/.claude/projects/) · Gemini CLI (~/.gemini/tmp/)\n'
          )
        );
        return;
      }

      // ── Header ────────────────────────────────────────────────────────────
      const rangeLabel = options.all
        ? chalk.dim('all time')
        : chalk.dim(`last ${options.days ?? 90} days`);
      const dateRange =
        scan.firstDate && scan.lastDate
          ? chalk.dim(`  ${fmtTs(scan.firstDate)} – ${fmtTs(scan.lastDate)}`)
          : '';

      const sessionBreakdown =
        claudeScan.sessions > 0 && geminiScan.sessions > 0
          ? chalk.dim('(') +
            chalk.cyan(String(claudeScan.sessions)) +
            chalk.dim(' Claude · ') +
            chalk.blue(String(geminiScan.sessions)) +
            chalk.dim(' Gemini)')
          : '';

      console.log(
        '  ' +
          chalk.white(num(scan.sessions)) +
          chalk.dim(' sessions  ') +
          sessionBreakdown +
          (sessionBreakdown ? '  ' : '') +
          chalk.white(num(scan.totalToolCalls)) +
          chalk.dim(' tool calls  ') +
          chalk.white(num(scan.bashCalls)) +
          chalk.dim(' bash commands  ') +
          rangeLabel +
          dateRange
      );
      console.log('');

      // ── Group findings by sourceType + shieldName ─────────────────────────
      const totalFindings = scan.findings.length;
      const blockedCount = scan.findings.filter((f) => f.source.rule.verdict === 'block').length;
      const reviewCount = totalFindings - blockedCount;

      if (totalFindings === 0 && scan.dlpFindings.length === 0) {
        console.log(chalk.green('  ✅ No findings across all shields and rules.'));
        console.log(chalk.dim('  node9 is still worth running — it monitors in real time.\n'));
      } else {
        // ── Headline summary ───────────────────────────────────────────────
        console.log('  ' + chalk.bold('What node9 would have done:'));
        console.log('');
        if (blockedCount > 0) {
          console.log(
            '    ' +
              chalk.red('🛑  Blocked') +
              '          ' +
              chalk.red.bold(String(blockedCount).padStart(5)) +
              chalk.dim('   operations stopped before execution')
          );
        }
        if (reviewCount > 0) {
          console.log(
            '    ' +
              chalk.yellow('👁   Reviewed') +
              '         ' +
              chalk.yellow.bold(String(reviewCount).padStart(5)) +
              chalk.dim('   flagged for human approval')
          );
        }
        if (scan.dlpFindings.length > 0) {
          console.log(
            '    ' +
              chalk.red('🔑  Credential leak') +
              '  ' +
              chalk.red.bold(String(scan.dlpFindings.length).padStart(5)) +
              chalk.dim('   secret detected in tool call')
          );
        }
        console.log('');

        // ── Separate findings by section ───────────────────────────────────
        const sections: Array<{
          label: string;
          subtitle: string;
          shieldKey?: string;
          findings: Finding[];
        }> = [];

        // Default rules section
        const defaultFindings = scan.findings.filter((f) => f.source.sourceType === 'default');
        if (defaultFindings.length > 0) {
          sections.push({
            label: 'Default Rules',
            subtitle: 'built-in, always on',
            findings: defaultFindings,
          });
        }

        // Shield sections — full section for shields with findings, one summary line if none
        const byShield = new Map<string, Finding[]>();
        for (const f of scan.findings.filter((f) => f.source.sourceType === 'shield')) {
          const arr = byShield.get(f.source.shieldName) ?? [];
          arr.push(f);
          byShield.set(f.source.shieldName, arr);
        }
        const shieldsWithFindings = [...byShield.entries()].sort(
          (a, b) => b[1].length - a[1].length
        );
        for (const [shieldName, findings] of shieldsWithFindings) {
          const description = SHIELDS[shieldName]?.description ?? '';
          sections.push({
            label: shieldName,
            subtitle: description,
            shieldKey: shieldName,
            findings,
          });
        }

        // User rules section
        const userFindings = scan.findings.filter(
          (f) => f.source.sourceType === 'user' || f.source.shieldName === 'cloud'
        );
        if (userFindings.length > 0) {
          sections.push({
            label: 'Your Rules',
            subtitle: 'added in node9.config.json',
            findings: userFindings,
          });
        }

        // ── Print each section ─────────────────────────────────────────────
        for (const section of sections) {
          const sectionBlocked = section.findings.filter(
            (f) => f.source.rule.verdict === 'block'
          ).length;
          const sectionReview = section.findings.length - sectionBlocked;

          const countParts: string[] = [];
          if (sectionBlocked > 0) countParts.push(chalk.red(`${sectionBlocked} blocked`));
          if (sectionReview > 0) countParts.push(chalk.yellow(`${sectionReview} review`));
          const countStr = countParts.join(chalk.dim(' · '));

          const enableHint = section.shieldKey
            ? chalk.dim(`  →  node9 shield enable ${section.shieldKey}`)
            : '';

          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' +
              chalk.bold(section.label) +
              (section.subtitle ? chalk.dim(`  ·  ${section.subtitle}`) : '') +
              '  ' +
              countStr +
              enableHint
          );

          // Group by rule, blocks first then reviews
          const byRule = new Map<string, Finding[]>();
          for (const f of section.findings) {
            const ruleKey = f.source.rule.name ?? 'unnamed';
            const arr = byRule.get(ruleKey) ?? [];
            arr.push(f);
            byRule.set(ruleKey, arr);
          }

          // Sort: block rules first, then by count desc
          const sortedRules = [...byRule.entries()].sort((a, b) => {
            const aBlock = a[1][0].source.rule.verdict === 'block' ? 1 : 0;
            const bBlock = b[1][0].source.rule.verdict === 'block' ? 1 : 0;
            if (bBlock !== aBlock) return bBlock - aBlock;
            return b[1].length - a[1].length;
          });

          for (const [, ruleFindings] of sortedRules) {
            printRuleGroup(ruleFindings, topN, drillDown, previewWidth);
          }
          console.log('');
        }

        // ── Shields with no findings — compact summary line ───────────────
        const emptyShields = Object.keys(SHIELDS)
          .filter((n) => !byShield.has(n))
          .sort();
        if (emptyShields.length > 0) {
          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' +
              chalk.bold('Shields') +
              chalk.dim('  ·  no findings in your history') +
              '  ' +
              chalk.green('✓')
          );
          console.log('  ' + chalk.dim(emptyShields.join(' · ')));
          console.log('  ' + chalk.dim('→  node9 shield enable <name>  to activate any shield'));
          console.log('');
        }

        // ── DLP findings ───────────────────────────────────────────────────
        if (scan.dlpFindings.length > 0) {
          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' +
              chalk.red.bold('🔑  Credential Leaks') +
              chalk.dim('  ·  ') +
              chalk.red(
                `${num(scan.dlpFindings.length)} potential secret leak${scan.dlpFindings.length !== 1 ? 's' : ''}`
              )
          );
          const shownDlp = drillDown ? scan.dlpFindings : scan.dlpFindings.slice(0, topN);
          for (const f of shownDlp) {
            const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
            const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
            const agentBadge =
              f.agent === 'gemini' ? chalk.blue('[Gemini]  ') : chalk.cyan('[Claude]  ');
            const sessionSuffix = f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
            console.log(
              `    ${ts}${proj}${agentBadge}` +
                chalk.yellow(f.patternName) +
                chalk.dim('  ') +
                chalk.gray(f.redactedSample) +
                sessionSuffix
            );
          }
          if (!drillDown && scan.dlpFindings.length > topN) {
            console.log(
              chalk.dim(
                `    … and ${scan.dlpFindings.length - topN} more  (--drill-down for full list)`
              )
            );
          }
          console.log('');
        }
      }

      // ── Cost ──────────────────────────────────────────────────────────────
      if (scan.totalCostUSD > 0) {
        console.log(
          '  ' +
            chalk.bold('Agent spend:') +
            '  ' +
            chalk.yellow(fmtCost(scan.totalCostUSD)) +
            chalk.dim('  (for per-period breakdown: node9 report)')
        );
        console.log('');
      }

      // ── CTA ───────────────────────────────────────────────────────────────
      const auditLog = path.join(os.homedir(), '.node9', 'audit.log');
      if (fs.existsSync(auditLog)) {
        console.log(chalk.green('  ✅ node9 is active — future sessions are protected.'));
        console.log(
          chalk.dim('  Run ') + chalk.cyan('node9 report') + chalk.dim(' to see live stats.')
        );
      } else {
        console.log(chalk.yellow.bold('  ⚡ node9 was not running during these sessions.'));
        console.log(
          '  ' +
            chalk.white('Run ') +
            chalk.cyan('node9 init') +
            chalk.white(' to start protecting your AI agents.')
        );
      }
      if (drillDown) {
        console.log(
          chalk.dim('  Run ') +
            chalk.cyan('node9 sessions --detail <session-id>') +
            chalk.dim(' to see the full conversation for any session above.')
        );
      } else {
        console.log(
          chalk.dim('  Run ') +
            chalk.cyan('node9 scan --drill-down') +
            chalk.dim(' to see full commands and session IDs.')
        );
      }
      console.log('');
    });
}
