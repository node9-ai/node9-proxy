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
import { isDaemonRunning, getInternalToken, DAEMON_PORT, DAEMON_HOST } from '../../auth/daemon';
import { openBrowserLocal, isTestingMode } from '../daemon-starter';
import { buildScanSummary, type FindingRef, type RuleGroup } from '../../scan-summary';
import { getAgentsStatus } from '../../setup';

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
  agent: 'claude' | 'gemini' | 'codex';
}

interface DlpFinding {
  patternName: string;
  redactedSample: string;
  toolName: string;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: 'claude' | 'gemini' | 'codex' | 'shell';
}

export interface LoopFinding {
  toolName: string;
  commandPreview: string;
  count: number;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: 'claude' | 'gemini' | 'codex';
}

interface JournalEntry {
  type: string;
  timestamp?: string;
  message?: {
    model?: string;
    content?: Array<{
      type: string;
      id?: string;
      name?: string;
      input?: Record<string, unknown>;
      // tool_result fields (present in user-role entries)
      tool_use_id?: string;
      content?: string | Array<{ type: string; text?: string }>;
    }>;
    usage?: {
      input_tokens?: number;
      output_tokens?: number;
      cache_creation_input_tokens?: number;
      cache_read_input_tokens?: number;
    };
  };
}

export interface ScanResult {
  filesScanned: number;
  sessions: number;
  totalToolCalls: number;
  bashCalls: number;
  findings: Finding[];
  dlpFindings: DlpFinding[];
  loopFindings: LoopFinding[];
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
// Constants
// ---------------------------------------------------------------------------

// File extensions whose contents are skipped for DLP scanning.
// Source code files contain auth patterns (template literals, test fixtures)
// that look like secrets but are not.
const CODE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.rb',
  '.go',
  '.rs',
  '.java',
  '.kt',
  '.swift',
  '.c',
  '.cpp',
  '.h',
  '.cs',
  '.php',
  '.sh',
  '.bash',
  '.html',
  '.css',
  '.scss',
  '.vue',
  '.svelte',
]);

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

// ---------------------------------------------------------------------------
// Loop detection
// ---------------------------------------------------------------------------

const LOOP_TOOLS = new Set([
  'bash',
  'execute_bash',
  'exec_command',
  'shell',
  'run_shell_command',
  'write',
  'edit',
  'multiedit',
]);
const LOOP_THRESHOLD = 3;

function detectLoops(
  calls: Array<{ toolName: string; input: Record<string, unknown>; timestamp: string }>,
  project: string,
  sessionId: string,
  agent: 'claude' | 'gemini' | 'codex'
): LoopFinding[] {
  const counts = new Map<
    string,
    { count: number; timestamp: string; input: Record<string, unknown>; toolName: string }
  >();
  for (const call of calls) {
    const tl = call.toolName.toLowerCase();
    if (!LOOP_TOOLS.has(tl)) continue;
    const key = tl + '\0' + preview(call.input, 200);
    const entry = counts.get(key) ?? {
      count: 0,
      timestamp: call.timestamp,
      input: call.input,
      toolName: call.toolName,
    };
    entry.count++;
    counts.set(key, entry);
  }
  const findings: LoopFinding[] = [];
  for (const [, entry] of counts) {
    if (entry.count >= LOOP_THRESHOLD) {
      findings.push({
        toolName: entry.toolName,
        commandPreview: preview(entry.input, 80),
        count: entry.count,
        timestamp: entry.timestamp,
        project,
        sessionId,
        agent,
      });
    }
  }
  return findings.sort((a, b) => b.count - a.count);
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

function countScanFiles(): number {
  let total = 0;
  const claudeDir = path.join(os.homedir(), '.claude', 'projects');
  if (fs.existsSync(claudeDir)) {
    try {
      for (const proj of fs.readdirSync(claudeDir)) {
        const p = path.join(claudeDir, proj);
        try {
          if (!fs.statSync(p).isDirectory()) continue;
          total += fs
            .readdirSync(p)
            .filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-')).length;
        } catch {
          continue;
        }
      }
    } catch {
      /* ignore */
    }
  }
  const geminiDir = path.join(os.homedir(), '.gemini', 'tmp');
  if (fs.existsSync(geminiDir)) {
    try {
      for (const slug of fs.readdirSync(geminiDir)) {
        const p = path.join(geminiDir, slug);
        try {
          if (!fs.statSync(p).isDirectory()) continue;
          const chatsDir = path.join(p, 'chats');
          if (fs.existsSync(chatsDir)) {
            try {
              total += fs.readdirSync(chatsDir).filter((f) => f.endsWith('.json')).length;
            } catch {
              /* ignore */
            }
          }
        } catch {
          continue;
        }
      }
    } catch {
      /* ignore */
    }
  }
  const codexDir = path.join(os.homedir(), '.codex', 'sessions');
  if (fs.existsSync(codexDir)) {
    try {
      for (const year of fs.readdirSync(codexDir)) {
        const yp = path.join(codexDir, year);
        try {
          if (!fs.statSync(yp).isDirectory()) continue;
          for (const month of fs.readdirSync(yp)) {
            const mp = path.join(yp, month);
            try {
              if (!fs.statSync(mp).isDirectory()) continue;
              for (const day of fs.readdirSync(mp)) {
                const dp = path.join(mp, day);
                try {
                  if (!fs.statSync(dp).isDirectory()) continue;
                  total += fs.readdirSync(dp).filter((f) => f.endsWith('.jsonl')).length;
                } catch {
                  continue;
                }
              }
            } catch {
              continue;
            }
          }
        } catch {
          continue;
        }
      }
    } catch {
      /* ignore */
    }
  }
  return total;
}

function renderProgressBar(done: number, total: number, lines: number): void {
  const width = 28;
  const pct = total > 0 ? done / total : 0;
  const filled = Math.min(width, Math.round(pct * width));
  const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
  const fileLabel = total > 0 ? `${done}/${total} files` : `${done} files`;
  const lineLabel = lines > 0 ? chalk.dim(`  ${lines.toLocaleString()} lines`) : '';
  process.stdout.write(
    `\r  ${chalk.cyan('Scanning')}  [${chalk.cyan(bar)}]  ${chalk.dim(fileLabel)}${lineLabel}  `
  );
}

export function scanClaudeHistory(
  startDate: Date | null,
  onProgress?: (done: number) => void,
  onLine?: () => void
): ScanResult {
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');

  const result: ScanResult = {
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
      onProgress?.(result.filesScanned);

      const sessionId = file.replace(/\.jsonl$/, '');

      let raw: string;
      try {
        raw = fs.readFileSync(path.join(projPath, file), 'utf-8');
      } catch {
        continue;
      }

      const sessionCalls: Array<{
        toolName: string;
        input: Record<string, unknown>;
        timestamp: string;
      }> = [];

      // Maps tool_use id → file extension so tool_result scanning can skip code files
      const toolUseFilePaths = new Map<string, string>();

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        onLine?.();

        let entry: JournalEntry;
        try {
          entry = JSON.parse(line) as JournalEntry;
        } catch {
          continue;
        }

        if (entry.type !== 'assistant' && entry.type !== 'user') continue;

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

        // ── User prompt DLP scan ───────────────────────────────────────────
        if (entry.type === 'user') {
          const content = entry.message?.content;
          if (Array.isArray(content)) {
            const text = content
              .filter((b) => b.type === 'text')
              .map((b) => (b as Record<string, unknown>)['text'] ?? '')
              .join('\n');
            if (text) {
              const dlpMatch = scanArgs({ text });
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
                    toolName: 'user-prompt',
                    timestamp: entry.timestamp ?? '',
                    project: projLabel,
                    sessionId,
                    agent: 'claude',
                  });
                }
              }
            }

            // ── Tool result DLP scan ─────────────────────────────────────
            // Secrets that Claude read back (file contents, command output)
            // are stored in tool_result blocks inside user-role entries.
            // Skip code files — they contain auth patterns in source code
            // that are not real secrets (template literals, test fixtures, etc.)
            for (const block of content) {
              if (block.type !== 'tool_result') continue;
              const filePath = block.tool_use_id
                ? toolUseFilePaths.get(block.tool_use_id)
                : undefined;
              if (filePath) {
                const ext = path.extname(filePath).toLowerCase();
                if (CODE_EXTENSIONS.has(ext)) continue;
              }
              const resultText =
                typeof block.content === 'string'
                  ? block.content
                  : Array.isArray(block.content)
                    ? block.content.map((c) => c.text ?? '').join('\n')
                    : null;
              if (!resultText) continue;
              const dlpMatch = scanArgs({ text: resultText });
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
                    toolName: 'tool-result',
                    timestamp: entry.timestamp ?? '',
                    project: projLabel,
                    sessionId,
                    agent: 'claude',
                  });
                }
              }
            }
          }
          continue;
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

          // Record file path for tool_result DLP filtering
          if (block.id && typeof input.file_path === 'string') {
            toolUseFilePaths.set(block.id, input.file_path);
          }

          sessionCalls.push({ toolName, input, timestamp: entry.timestamp ?? '' });

          if (toolNameLower === 'bash' || toolNameLower === 'execute_bash') {
            result.bashCalls++;
          }

          // Skip node9's own read-only CLI calls
          const rawCmd = String(input.command ?? '').trimStart();
          if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd))
            continue;

          // ── DLP scan ───────────────────────────────────────────────────
          // Skip code files — Edit/Write pass full source in old_string/new_string
          // which contains auth patterns that are not real secrets.
          const inputFilePath = typeof input.file_path === 'string' ? input.file_path : '';
          const inputFileExt = inputFilePath ? path.extname(inputFilePath).toLowerCase() : '';
          if (CODE_EXTENSIONS.has(inputFileExt)) continue;

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
      result.loopFindings.push(...detectLoops(sessionCalls, projLabel, sessionId, 'claude'));
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Gemini history scanner
// ---------------------------------------------------------------------------

export function scanGeminiHistory(
  startDate: Date | null,
  onProgress?: (done: number) => void,
  onLine?: () => void
): ScanResult {
  const tmpDir = path.join(os.homedir(), '.gemini', 'tmp');
  const result: ScanResult = {
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
      onProgress?.(result.filesScanned);

      const sessionId = chatFile.replace(/\.json$/, '');

      let raw: string;
      try {
        raw = fs.readFileSync(path.join(chatsDir, chatFile), 'utf-8');
      } catch {
        continue;
      }

      const sessionCalls: Array<{
        toolName: string;
        input: Record<string, unknown>;
        timestamp: string;
      }> = [];

      let session: GeminiSessionFile;
      try {
        session = JSON.parse(raw) as GeminiSessionFile;
      } catch {
        continue;
      }

      result.sessions++;

      for (const msg of session.messages ?? []) {
        onLine?.();
        // ── User prompt DLP scan ─────────────────────────────────────────
        if (msg.type === 'user') {
          const content = msg.content;
          const text = Array.isArray(content)
            ? content.map((c) => c.text ?? '').join('\n')
            : typeof content === 'string'
              ? content
              : '';
          if (text) {
            const dlpMatch = scanArgs({ text });
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
                  toolName: 'user-prompt',
                  timestamp: msg.timestamp ?? '',
                  project: projLabel,
                  sessionId,
                  agent: 'gemini',
                });
              }
            }
          }
          continue;
        }

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

          sessionCalls.push({ toolName, input, timestamp: msg.timestamp ?? '' });

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
      result.loopFindings.push(...detectLoops(sessionCalls, projLabel, sessionId, 'gemini'));
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Codex history scanner
// ---------------------------------------------------------------------------

export function scanCodexHistory(
  startDate: Date | null,
  onProgress?: (done: number) => void,
  onLine?: () => void
): ScanResult {
  const sessionsBase = path.join(os.homedir(), '.codex', 'sessions');
  const result: ScanResult = {
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
  };

  if (!fs.existsSync(sessionsBase)) return result;

  // Collect all .jsonl files under YYYY/MM/DD structure
  const jsonlFiles: string[] = [];
  try {
    for (const year of fs.readdirSync(sessionsBase)) {
      const yearPath = path.join(sessionsBase, year);
      try {
        if (!fs.statSync(yearPath).isDirectory()) continue;
      } catch {
        continue;
      }
      for (const month of fs.readdirSync(yearPath)) {
        const monthPath = path.join(yearPath, month);
        try {
          if (!fs.statSync(monthPath).isDirectory()) continue;
        } catch {
          continue;
        }
        for (const day of fs.readdirSync(monthPath)) {
          const dayPath = path.join(monthPath, day);
          try {
            if (!fs.statSync(dayPath).isDirectory()) continue;
          } catch {
            continue;
          }
          for (const file of fs.readdirSync(dayPath)) {
            if (file.endsWith('.jsonl')) jsonlFiles.push(path.join(dayPath, file));
          }
        }
      }
    }
  } catch {
    return result;
  }

  const ruleSources = buildRuleSources();

  for (const filePath of jsonlFiles) {
    result.filesScanned++;
    onProgress?.(result.filesScanned);

    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    } catch {
      continue;
    }

    let sessionId = '';
    let startTime = '';
    let projLabel = '';
    result.sessions++;

    const sessionCalls: Array<{
      toolName: string;
      input: Record<string, unknown>;
      timestamp: string;
    }> = [];

    // Track last cumulative token count for cost
    let lastTotalInput = 0;
    let lastTotalCached = 0;
    let lastTotalOutput = 0;

    for (const line of lines) {
      if (!line.trim()) continue;
      onLine?.();
      let entry: { type: string; timestamp?: string; payload?: Record<string, unknown> };
      try {
        entry = JSON.parse(line) as typeof entry;
      } catch {
        continue;
      }

      const payload = (entry.payload ?? {}) as Record<string, unknown>;

      if (entry.type === 'session_meta') {
        sessionId = String(payload['id'] ?? filePath);
        startTime = String(payload['timestamp'] ?? '');
        const cwd = String(payload['cwd'] ?? '');
        projLabel = cwd.replace(os.homedir(), '~').slice(0, 40);
        continue;
      }

      if (entry.type === 'event_msg' && payload['type'] === 'token_count') {
        const info = payload['info'] as Record<string, unknown> | null;
        const usage = (info?.['total_token_usage'] ?? {}) as Record<string, number>;
        lastTotalInput = usage['input_tokens'] ?? lastTotalInput;
        lastTotalCached = usage['cached_input_tokens'] ?? lastTotalCached;
        lastTotalOutput = usage['output_tokens'] ?? lastTotalOutput;
        continue;
      }

      // ── User prompt DLP scan ─────────────────────────────────────────────
      if (entry.type === 'event_msg' && payload['type'] === 'user_message') {
        const text = String(payload['message'] ?? '');
        if (text) {
          const dlpMatch = scanArgs({ text });
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
                toolName: 'user-prompt',
                timestamp: entry.timestamp ?? startTime,
                project: projLabel,
                sessionId,
                agent: 'codex',
              });
            }
          }
        }
        continue;
      }

      if (entry.type !== 'response_item') continue;
      if (payload['type'] !== 'function_call') continue;

      const ts = startTime;
      if (startDate && ts && new Date(ts) < startDate) continue;

      if (ts) {
        if (!result.firstDate || ts < result.firstDate) result.firstDate = ts;
        if (!result.lastDate || ts > result.lastDate) result.lastDate = ts;
      }

      result.totalToolCalls++;
      const toolName = String(payload['name'] ?? '');
      const toolNameLower = toolName.toLowerCase();

      let input: Record<string, unknown> = {};
      try {
        input = JSON.parse(String(payload['arguments'] ?? '{}')) as Record<string, unknown>;
      } catch {}

      // Codex uses 'cmd' — normalise to 'command' so existing rules fire correctly
      if ('cmd' in input && !('command' in input)) {
        input = { ...input, command: input['cmd'] };
      }

      sessionCalls.push({ toolName, input, timestamp: ts });

      if (toolNameLower === 'exec_command' || toolNameLower === 'shell') {
        result.bashCalls++;
      }

      const rawCmd = String(input['command'] ?? '').trimStart();
      if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd)) continue;

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
            timestamp: ts,
            project: projLabel,
            sessionId,
            agent: 'codex',
          });
        }
      }

      let ruleMatched = false;
      for (const source of ruleSources) {
        const { rule } = source;
        if (rule.verdict === 'allow') continue;
        if (
          rule.tool &&
          !matchesPattern(toolNameLower === 'exec_command' ? 'bash' : toolNameLower, rule.tool)
        )
          continue;
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
            timestamp: ts,
            project: projLabel,
            sessionId,
            agent: 'codex',
          });
        }
        ruleMatched = true;
        break;
      }

      if (!ruleMatched && (toolNameLower === 'exec_command' || toolNameLower === 'shell')) {
        const shellVerdict = detectDangerousShellExec(String(input['command'] ?? ''));
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
              timestamp: ts,
              project: projLabel,
              sessionId,
              agent: 'codex',
            });
          }
        }
      }
    }

    // Accumulate session cost using GPT-4o pricing as proxy for codex-1/GPT-5
    const nonCached = Math.max(0, lastTotalInput - lastTotalCached);
    result.totalCostUSD += nonCached * 5e-6 + lastTotalCached * 2.5e-6 + lastTotalOutput * 15e-6;

    result.loopFindings.push(...detectLoops(sessionCalls, projLabel, sessionId, 'codex'));
  }

  return result;
}

function scanShellConfig(): DlpFinding[] {
  const home = os.homedir();
  const configFiles = ['.zshrc', '.bashrc', '.bash_profile', '.profile'].map((f) =>
    path.join(home, f)
  );
  const findings: DlpFinding[] = [];

  for (const filePath of configFiles) {
    if (!fs.existsSync(filePath)) continue;
    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    } catch {
      continue;
    }
    const shortPath = filePath.replace(home, '~');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const dlpMatch = scanArgs({ text: trimmed });
      if (!dlpMatch) continue;
      const isDupe = findings.some(
        (f) =>
          f.patternName === dlpMatch.patternName &&
          f.redactedSample === dlpMatch.redactedSample &&
          f.project === shortPath
      );
      if (!isDupe) {
        findings.push({
          patternName: dlpMatch.patternName,
          redactedSample: dlpMatch.redactedSample,
          toolName: 'shell-config',
          timestamp: '',
          project: shortPath,
          sessionId: '',
          agent: 'shell',
        });
      }
    }
  }
  return findings;
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
    loopFindings: [...a.loopFindings, ...b.loopFindings],
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
  f: FindingRef,
  drillDown: boolean,
  showSessionId: boolean,
  previewWidth: number
): void {
  const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
  const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
  const agentBadge =
    f.agent === 'gemini'
      ? chalk.blue('[Gemini]  ')
      : f.agent === 'codex'
        ? chalk.magenta('[Codex]   ')
        : chalk.cyan('[Claude]  ');
  // FindingRef.command is already the preview; fullCommand is the untruncated form.
  let cmdText: string;
  if (drillDown) {
    cmdText = f.fullCommand;
  } else {
    cmdText = f.command;
    if (cmdText.length > previewWidth) cmdText = cmdText.slice(0, previewWidth - 1) + '…';
  }
  const cmd = chalk.gray(cmdText);
  const sessionSuffix =
    showSessionId && f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
  console.log(`      ${ts}${proj}${agentBadge}${cmd}${sessionSuffix}`);
}

function printRuleGroup(
  rule: RuleGroup,
  topN: number,
  drillDown: boolean,
  previewWidth: number
): void {
  const findings = rule.findings;
  const ruleCount = findings.length;
  const countBadge = ruleCount > 1 ? chalk.white(` ×${ruleCount}`) : '';
  const icon = verdictIcon(rule.verdict);
  console.log(
    '    ' +
      icon +
      '  ' +
      chalk.white(rule.name) +
      countBadge +
      (rule.reason ? chalk.dim(`  — ${rule.reason}`) : '')
  );

  const shown = drillDown ? findings : findings.slice(0, topN);
  for (const f of shown) {
    printFindingRow(f, drillDown, drillDown, previewWidth);
  }
  if (!drillDown && findings.length > topN) {
    console.log(
      chalk.dim(`      … and ${findings.length - topN} more  (--drill-down for full list)`)
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
    .option('--all', 'Scan all history (default: last 30 days)')
    .option('--days <n>', 'Scan last N days of history', '30')
    .option('--top <n>', 'Max findings to show per rule (default: 5)', '5')
    .option('--drill-down', 'Show all findings with full commands and session IDs')
    .action(async (options: { all?: boolean; days: string; top: string; drillDown?: boolean }) => {
      const drillDown = options.drillDown ?? false;
      const topN = drillDown ? Infinity : Math.max(1, parseInt(options.top, 10) || 5);
      const previewWidth = 70;
      const startDate = options.all
        ? null
        : (() => {
            const d = new Date();
            d.setDate(d.getDate() - (parseInt(options.days, 10) || 30));
            d.setHours(0, 0, 0, 0);
            return d;
          })();

      // "Wired" = node9 hooks are actually installed in at least one agent's
      // settings file (~/.claude/settings.json, ~/.gemini/settings.json, etc.).
      // This is the real signal that future sessions are protected — checking
      // for ~/.node9/audit.log alone falsely treats npx users as installed
      // after their first run.
      const isWired = getAgentsStatus().some((a) => a.wired);

      console.log('');
      if (!isWired) {
        console.log(
          chalk.bold('🛡  node9') + chalk.dim('  —  security layer for AI coding agents')
        );
        console.log(
          chalk.dim('   Intercepts dangerous tool calls before they execute. No config needed.')
        );
        console.log('');
      }
      console.log(
        chalk.cyan.bold('🔍  Scanning your AI history') +
          chalk.dim('  — what would node9 have caught?')
      );
      console.log('');

      const useTTY = process.stdout.isTTY === true && process.env.NODE9_WRAPPER !== '1';
      if (!useTTY) {
        process.stdout.write(
          '  ' + chalk.dim('Scanning your history — this may take a moment...\n')
        );
      }

      const totalFiles = countScanFiles();
      let filesScanned = 0;
      let linesScanned = 0;
      let lastRender = 0;
      const onProgress = (done: number) => {
        filesScanned = done;
        if (useTTY) renderProgressBar(filesScanned, totalFiles, linesScanned);
        lastRender = Date.now();
      };
      const onLine = () => {
        linesScanned++;
        const now = Date.now();
        if (useTTY && now - lastRender >= 80) {
          lastRender = now;
          renderProgressBar(filesScanned, totalFiles, linesScanned);
        }
      };
      if (useTTY) renderProgressBar(0, totalFiles, 0);
      const claudeScan = scanClaudeHistory(startDate, onProgress, onLine);
      const geminiScan = scanGeminiHistory(
        startDate,
        (done) => onProgress(claudeScan.filesScanned + done),
        onLine
      );
      const codexScan = scanCodexHistory(
        startDate,
        (done) => onProgress(claudeScan.filesScanned + geminiScan.filesScanned + done),
        onLine
      );
      const scan = mergeScans(mergeScans(claudeScan, geminiScan), codexScan);
      scan.dlpFindings.push(...scanShellConfig());
      const summary = buildScanSummary([
        { id: 'claude', label: 'Claude', icon: '🤖', scan: claudeScan },
        { id: 'gemini', label: 'Gemini', icon: '♊', scan: geminiScan },
        { id: 'codex', label: 'Codex', icon: '🔮', scan: codexScan },
      ]);
      if (useTTY) process.stdout.write('\r' + ' '.repeat(60) + '\r');

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
        : chalk.dim(`last ${options.days ?? 30} days`);
      const dateRange =
        scan.firstDate && scan.lastDate
          ? chalk.dim(`  ${fmtTs(scan.firstDate)} – ${fmtTs(scan.lastDate)}`)
          : '';

      const breakdownParts: string[] = [];
      if (claudeScan.sessions > 0)
        breakdownParts.push(chalk.cyan(String(claudeScan.sessions)) + chalk.dim(' Claude'));
      if (geminiScan.sessions > 0)
        breakdownParts.push(chalk.blue(String(geminiScan.sessions)) + chalk.dim(' Gemini'));
      if (codexScan.sessions > 0)
        breakdownParts.push(chalk.magenta(String(codexScan.sessions)) + chalk.dim(' Codex'));
      const sessionBreakdown =
        breakdownParts.length > 1
          ? chalk.dim('(') + breakdownParts.join(chalk.dim(' · ')) + chalk.dim(')')
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
        console.log(chalk.green('  ✅ No risky operations found in your history.'));
        console.log(
          chalk.dim('  node9 is still worth running — it monitors every tool call in real time.\n')
        );
      } else {
        // ── Hero headline ──────────────────────────────────────────────────
        const totalRisky = totalFindings + scan.dlpFindings.length;
        const heroLine = isWired
          ? chalk.bold(
              `  Found ${chalk.yellow(String(totalRisky))} risky operation${totalRisky !== 1 ? 's' : ''} in your history`
            )
          : chalk.bold(
              `  ${chalk.red.bold(String(totalRisky))} risky operation${totalRisky !== 1 ? 's' : ''} found — none were blocked`
            );
        console.log(heroLine);
        console.log('');

        // ── Summary breakdown — ordered by impact ──────────────────────────
        if (scan.totalCostUSD > 0) {
          console.log(
            '    ' +
              chalk.bold(fmtCost(scan.totalCostUSD)) +
              chalk.dim(' AI spend  ·  ') +
              chalk.dim(`${totalRisky} risky operations`)
          );
        }
        if (scan.dlpFindings.length > 0) {
          console.log(
            '    ' +
              chalk.red('🔑  Credential leak') +
              '     ' +
              chalk.red.bold(String(scan.dlpFindings.length).padStart(5)) +
              chalk.dim('   secret detected in history or shell config')
          );
        }
        if (blockedCount > 0) {
          console.log(
            '    ' +
              chalk.red('🛑  Would have blocked') +
              '   ' +
              chalk.red.bold(String(blockedCount).padStart(5)) +
              chalk.dim('   operations stopped before execution')
          );
        }
        if (scan.loopFindings.length > 0) {
          const loopCost =
            summary.loopWastedUSD > 0
              ? chalk.dim('  ·  ') + chalk.yellow('~' + fmtCost(summary.loopWastedUSD) + ' wasted')
              : '';
          console.log(
            '    ' +
              chalk.yellow('🔁  Loop detected') +
              '      ' +
              chalk.yellow.bold(String(scan.loopFindings.length).padStart(5)) +
              chalk.dim('   repeated tool call patterns found') +
              loopCost
          );
        }
        if (reviewCount > 0) {
          console.log(
            '    ' +
              chalk.yellow('👁   Would have flagged') +
              '   ' +
              chalk.yellow.bold(String(reviewCount).padStart(5)) +
              chalk.dim('   sent to you for approval')
          );
        }
        console.log('');

        // ── Credential Leaks — first, most alarming ───────────────────────
        if (scan.dlpFindings.length > 0) {
          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' +
              chalk.red.bold('🔑  Credential Leaks') +
              chalk.dim('  ·  ') +
              chalk.red(
                `${num(scan.dlpFindings.length)} secret${scan.dlpFindings.length !== 1 ? 's' : ''} found in plain text`
              )
          );
          const shownDlp = drillDown ? scan.dlpFindings : scan.dlpFindings.slice(0, topN);
          for (const f of shownDlp) {
            const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
            const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
            const agentBadge =
              f.agent === 'gemini'
                ? chalk.blue('[Gemini]  ')
                : f.agent === 'codex'
                  ? chalk.magenta('[Codex]   ')
                  : f.agent === 'shell'
                    ? chalk.yellow('[Shell]   ')
                    : chalk.cyan('[Claude]  ');
            const sessionSuffix = f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
            console.log(
              `    🚨 ${ts}${proj}${agentBadge}` +
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

        // ── Blocked operations — consolidated across all rule sources ─────
        const blockedRuleSections = summary.sections
          .map((s) => ({ ...s, rules: s.rules.filter((r) => r.verdict === 'block') }))
          .filter((s) => s.rules.length > 0);
        if (blockedRuleSections.length > 0) {
          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' +
              chalk.red.bold('🛑  Blocked') +
              chalk.dim('  ·  ') +
              chalk.red(
                `${blockedCount} operation${blockedCount !== 1 ? 's' : ''} node9 would have stopped`
              )
          );
          for (const section of blockedRuleSections) {
            for (const rule of section.rules) {
              printRuleGroup(rule, topN, drillDown, previewWidth);
            }
          }
          console.log('');
        }

        // ── Agent Loops ────────────────────────────────────────────────────
        if (scan.loopFindings.length > 0) {
          console.log('  ' + chalk.dim('─'.repeat(70)));
          const loopCostLabel =
            summary.loopWastedUSD > 0
              ? chalk.dim('  ·  ') + chalk.yellow('~' + fmtCost(summary.loopWastedUSD) + ' wasted')
              : '';
          console.log(
            '  ' +
              chalk.yellow.bold('🔁  Agent Loops') +
              chalk.dim('  ·  ') +
              chalk.yellow(
                `${num(scan.loopFindings.length)} repeated pattern${scan.loopFindings.length !== 1 ? 's' : ''} found`
              ) +
              loopCostLabel
          );
          const shownLoops = drillDown ? scan.loopFindings : scan.loopFindings.slice(0, topN);
          for (const f of shownLoops) {
            const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
            const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
            const agentBadge =
              f.agent === 'gemini'
                ? chalk.blue('[Gemini]  ')
                : f.agent === 'codex'
                  ? chalk.magenta('[Codex]   ')
                  : chalk.cyan('[Claude]  ');
            const sessionSuffix = f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
            console.log(
              `    ${ts}${proj}${agentBadge}` +
                chalk.yellow(f.toolName) +
                chalk.dim(`  ×${f.count}  `) +
                chalk.gray(f.commandPreview) +
                sessionSuffix
            );
          }
          if (!drillDown && scan.loopFindings.length > topN) {
            console.log(
              chalk.dim(
                `    … and ${scan.loopFindings.length - topN} more  (--drill-down for full list)`
              )
            );
          }
          console.log('');
        }

        // ── Flagged for review — review-verdict rules only ─────────────────
        for (const section of summary.sections) {
          const reviewRules = section.rules.filter((r) => r.verdict !== 'block');
          if (reviewRules.length === 0) continue;
          const enableHint = section.shieldKey
            ? chalk.dim(`  →  node9 shield enable ${section.shieldKey}`)
            : '';
          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' +
              chalk.bold(section.label) +
              (section.subtitle ? chalk.dim(`  ·  ${section.subtitle}`) : '') +
              '  ' +
              chalk.yellow(`${section.reviewCount} review`) +
              enableHint
          );
          for (const rule of reviewRules) {
            printRuleGroup(rule, topN, drillDown, previewWidth);
          }
          console.log('');
        }

        // ── Inactive Shields — upsell, always last ─────────────────────────
        const activeShieldIds = new Set(
          summary.sections
            .filter((s) => s.sourceType === 'shield' && s.shieldKey)
            .map((s) => s.shieldKey!)
        );
        const emptyShields = Object.keys(SHIELDS)
          .filter((n) => !activeShieldIds.has(n))
          .sort();
        if (emptyShields.length > 0) {
          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' + chalk.bold('🛡  Inactive Shields') + chalk.dim('  ·  enable for more coverage')
          );
          console.log('  ' + chalk.dim(emptyShields.join(' · ')));
          console.log('  ' + chalk.dim('→  node9 shield enable <name>  to activate'));
          console.log('');
        }
      }

      // ── CTA ───────────────────────────────────────────────────────────────
      if (isWired) {
        console.log(chalk.green('  ✅ node9 is active — your future sessions are protected.'));
        console.log(
          chalk.dim('  Run ') +
            chalk.cyan('node9 report') +
            chalk.dim(' to see live protection stats.')
        );
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
      } else {
        const riskySummary = totalFindings + scan.dlpFindings.length;
        if (riskySummary > 0) {
          console.log(
            chalk.yellow.bold(
              `  ⚡ ${riskySummary} operation${riskySummary !== 1 ? 's' : ''} ran unprotected.`
            ) + chalk.dim(' node9 would have caught them.')
          );
        }
        console.log('');
        console.log(chalk.bold('  Protect your next session in 30 seconds:'));
        console.log('');
        console.log('    ' + chalk.cyan('npm install -g @node9/proxy'));
        console.log('    ' + chalk.cyan('node9 init'));
        console.log('');
        console.log(chalk.dim('  node9 hooks into Claude Code automatically.'));
        console.log(
          chalk.dim('  Every tool call is checked before it runs — no proxy, no latency.')
        );
        console.log('');
        console.log('  ' + chalk.dim('→ ') + chalk.underline('https://node9.ai'));
      }
      console.log('');

      if (!isTestingMode()) {
        if (isWired) {
          const url = `http://${DAEMON_HOST}:${DAEMON_PORT}/?openscan=1`;
          if (isDaemonRunning()) {
            const internalToken = getInternalToken();
            if (internalToken) {
              try {
                const pushSummary = buildScanSummary([
                  { id: 'claude', label: 'Claude', icon: '🤖', scan: claudeScan },
                  { id: 'gemini', label: 'Gemini', icon: '♊', scan: geminiScan },
                  { id: 'codex', label: 'Codex', icon: '🔮', scan: codexScan },
                ]);
                await fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/scan/push`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'x-node9-internal': internalToken,
                  },
                  body: JSON.stringify({ status: 'complete', summary: pushSummary }),
                  signal: AbortSignal.timeout(3000),
                });
                openBrowserLocal();
              } catch {
                // fire-and-forget
              }
            }
          }
          if (isDaemonRunning()) {
            console.log('  ' + chalk.cyan('🌐 View in browser:') + '  ' + chalk.underline(url));
          } else {
            console.log(
              '  ' +
                chalk.dim('📊 To view in browser, start the daemon:  ') +
                chalk.cyan('node9 daemon --background')
            );
          }
          console.log('');
        }
        // When not wired, the install CTA above is the next step — no browser hint.
      }
    });
}
