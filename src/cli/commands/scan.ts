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
import { getConfig } from '../../config';
import { evaluateSmartConditions, matchesPattern } from '../../policy/index';
import { scanArgs } from '../../dlp';
import type { SmartRule } from '../../core';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RuleSource {
  shieldName: string; // "bash-safe" | "custom" | "cloud"
  shieldLabel: string; // display label
  rule: SmartRule;
}

interface Finding {
  source: RuleSource;
  toolName: string;
  input: Record<string, unknown>;
  timestamp: string;
  project: string;
}

interface DlpFinding {
  patternName: string;
  redactedSample: string;
  toolName: string;
  timestamp: string;
  project: string;
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
// Build the rule set for scan
// ---------------------------------------------------------------------------
// Includes:
//   1. All builtin + user shields (regardless of active state) — the forecast
//   2. User custom smart rules from config.json + cloud rules from rules-cache.json
//      (rules NOT from shields, identified by names not starting with "shield:")

function buildRuleSources(): RuleSource[] {
  const sources: RuleSource[] = [];

  // 1. All shields (builtin + user-installed)
  for (const [shieldName, shield] of Object.entries(SHIELDS)) {
    for (const rule of shield.smartRules) {
      sources.push({ shieldName, shieldLabel: shieldName, rule });
    }
  }

  // 2. User custom rules + cloud rules (anything not from a shield)
  try {
    const config = getConfig();
    for (const rule of config.policy.smartRules) {
      if (!rule.name) continue;
      // Skip shield rules — already included above
      if (rule.name.startsWith('shield:')) continue;
      // Guess source label from name convention (cloud rules typically prefixed with "cloud:")
      const isCloud = rule.name.startsWith('cloud:');
      sources.push({
        shieldName: isCloud ? 'cloud' : 'custom',
        shieldLabel: isCloud ? 'Cloud Policy' : 'Your Rules',
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

          // Skip node9's own read-only CLI calls — they are dry-runs and
          // should never appear as findings. Match only known subcommands so
          // a command like `node9_wrapper` or `node9 ; rm -rf /` isn't excluded.
          const rawCmd = String(input.command ?? '').trimStart();
          if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd)) continue;

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
              });
            }
          }

          // ── Smart rule matching ────────────────────────────────────────
          for (const source of ruleSources) {
            const { rule } = source;

            // Allow rules are not catches — skip them
            if (rule.verdict === 'allow') continue;

            // Tool name must match the rule's tool pattern
            if (rule.tool && !matchesPattern(toolNameLower, rule.tool)) continue;

            if (!evaluateSmartConditions(input, rule)) continue;

            // Deduplicate: same rule + same input preview + same project
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
              });
            }

            break; // First matching rule wins per tool call
          }
        }
      }
    }
  }

  return result;
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
    .option('--top <n>', 'Max findings to show per shield', '5')
    .action((options: { all?: boolean; days: string; top: string }) => {
      const topN = Math.max(1, parseInt(options.top, 10) || 5);
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

      const projectsDir = path.join(os.homedir(), '.claude', 'projects');
      if (!fs.existsSync(projectsDir)) {
        console.log(chalk.yellow('  No Claude history found at ~/.claude/projects/'));
        console.log(chalk.gray('  Install Claude Code, run a few sessions, then try again.\n'));
        return;
      }

      process.stdout.write(chalk.dim('  Scanning…'));
      const scan = scanClaudeHistory(startDate);
      process.stdout.write('\r' + ' '.repeat(20) + '\r');

      if (scan.filesScanned === 0) {
        console.log(chalk.yellow('  No JSONL session files found.\n'));
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

      console.log(
        '  ' +
          chalk.white(num(scan.sessions)) +
          chalk.dim(' sessions  ') +
          chalk.white(num(scan.totalToolCalls)) +
          chalk.dim(' tool calls  ') +
          chalk.white(num(scan.bashCalls)) +
          chalk.dim(' bash commands  ') +
          rangeLabel +
          dateRange
      );
      console.log('');

      // ── Group findings by shield ───────────────────────────────────────────
      const byShield = new Map<string, { label: string; findings: Finding[] }>();
      for (const f of scan.findings) {
        const key = f.source.shieldName;
        const entry = byShield.get(key) ?? { label: f.source.shieldLabel, findings: [] };
        entry.findings.push(f);
        byShield.set(key, entry);
      }

      const totalFindings = scan.findings.length;

      if (totalFindings === 0 && scan.dlpFindings.length === 0) {
        console.log(chalk.green('  ✅ No findings across all shields and rules.'));
        console.log(chalk.dim('  node9 is still worth running — it monitors in real time.\n'));
      } else {
        if (totalFindings > 0) {
          console.log(
            '  ' +
              chalk.bold('If node9 had been installed:') +
              '  ' +
              chalk.yellow.bold(
                `${num(totalFindings)} command${totalFindings !== 1 ? 's' : ''} flagged for review`
              )
          );
          console.log('');

          // Sort shields: most findings first
          const sorted = [...byShield.entries()].sort(
            (a, b) => b[1].findings.length - a[1].findings.length
          );

          for (const [shieldName, { label, findings }] of sorted) {
            const count = findings.length;
            const isUserRule = shieldName === 'custom' || shieldName === 'cloud';
            const shieldBadge = isUserRule ? chalk.magenta(label) : chalk.cyan(label);

            console.log('  ' + chalk.dim('─'.repeat(70)));
            console.log(
              '  ' +
                shieldBadge +
                chalk.dim('  ·  ') +
                chalk.yellow(`${num(count)} finding${count !== 1 ? 's' : ''}`) +
                (isUserRule ? '' : chalk.dim(`  →  node9 shield enable ${shieldName}`))
            );

            // Group by rule within the shield
            const byRule = new Map<string, Finding[]>();
            for (const f of findings) {
              const ruleKey = f.source.rule.name ?? 'unnamed';
              const arr = byRule.get(ruleKey) ?? [];
              arr.push(f);
              byRule.set(ruleKey, arr);
            }

            for (const [, ruleFindings] of byRule) {
              const rule = ruleFindings[0].source.rule;
              const ruleCount = ruleFindings.length;
              const countBadge = ruleCount > 1 ? chalk.white(` ×${ruleCount}`) : '';
              // Display the short rule name: strip "shield:<name>:" prefix
              const shortName = (rule.name ?? 'unnamed').replace(/^shield:[^:]+:/, '');
              console.log(
                '    ' +
                  chalk.white(shortName) +
                  countBadge +
                  (rule.reason ? chalk.dim(`  — ${rule.reason}`) : '')
              );

              const shown = ruleFindings.slice(0, topN);
              for (const f of shown) {
                const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
                const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
                const cmd = chalk.gray(preview(f.input, 55));
                console.log(`      ${ts}${proj}${cmd}`);
              }
              if (ruleFindings.length > topN) {
                console.log(
                  chalk.dim(
                    `      … and ${ruleFindings.length - topN} more (--top ${ruleFindings.length})`
                  )
                );
              }
            }
            console.log('');
          }
        }

        // ── DLP findings ───────────────────────────────────────────────────
        if (scan.dlpFindings.length > 0) {
          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' +
              chalk.red.bold('Secrets / DLP') +
              chalk.dim('  ·  ') +
              chalk.red(
                `${num(scan.dlpFindings.length)} potential secret leak${scan.dlpFindings.length !== 1 ? 's' : ''}`
              )
          );
          const shownDlp = scan.dlpFindings.slice(0, topN);
          for (const f of shownDlp) {
            const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
            const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
            console.log(
              `    ${ts}${proj}` +
                chalk.yellow(f.patternName) +
                chalk.dim('  ') +
                chalk.gray(f.redactedSample)
            );
          }
          if (scan.dlpFindings.length > topN) {
            console.log(
              chalk.dim(
                `    … and ${scan.dlpFindings.length - topN} more (--top ${scan.dlpFindings.length})`
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
            chalk.bold('Claude spend:') +
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
      console.log('');
    });
}
