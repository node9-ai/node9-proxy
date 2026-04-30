// src/policy/index.ts
// Host wrapper around @node9/policy-engine.
//
// The policy waterfall (DLP, smart rules, eval detection, pipe-chain,
// provenance, sandbox, dangerous-words, strict mode) lives in the engine.
// This file:
//   - calls getConfig() / getActiveEnvironment() / readActiveShields()
//   - injects checkProvenance + isTrustedHost as host hooks
//   - keeps shouldSnapshot (Config-aware, hook-side concern)
//   - keeps the explainPolicy waterfall (heavy fs/os/process I/O)

import fs from 'fs';
import path from 'path';
import os from 'os';
import pm from 'picomatch';
import { scanArgs, scanFilePath } from '../dlp';
import { type Config, getConfig, getActiveEnvironment } from '../config';
import { checkProvenance } from '../utils/provenance.js';
import { isTrustedHost } from '../auth/trusted-hosts.js';
import {
  evaluatePolicy as engineEvaluatePolicy,
  isIgnoredTool as engineIsIgnoredTool,
  matchesPattern,
  evaluateSmartConditions,
  detectDangerousShellExec,
  analyzeShellCommand,
  type PolicyVerdict,
} from '@node9/policy-engine';

export {
  matchesPattern,
  evaluateSmartConditions,
  normalizeCommandForPolicy,
  detectDangerousShellExec,
  detectDangerousEval,
  checkDangerousSql,
} from '@node9/policy-engine';

// ── shouldSnapshot — Config-aware undo gate (host concern) ──────────────────

/**
 * Returns true if a snapshot should be taken for this tool call.
 * Checks: tool name match → ignorePaths → onlyPaths (if specified).
 */
export function shouldSnapshot(toolName: string, args: unknown, config: Config): boolean {
  if (!config.settings.enableUndo) return false;

  const snap = config.policy.snapshot;
  if (!snap.tools.includes(toolName.toLowerCase())) return false;

  const a = args && typeof args === 'object' ? (args as Record<string, unknown>) : {};
  const filePath = String(a.file_path ?? a.path ?? a.filename ?? '');

  if (filePath) {
    if (snap.ignorePaths.length && pm(snap.ignorePaths)(filePath)) return false;
    if (snap.onlyPaths.length && !pm(snap.onlyPaths)(filePath)) return false;
  }

  return true;
}

// ── evaluatePolicy — host wrapper that injects config + I/O hooks ───────────

export async function evaluatePolicy(
  toolName: string,
  args?: unknown,
  agent?: string,
  cwd?: string
): Promise<PolicyVerdict> {
  const config = getConfig();
  const activeEnvironment = getActiveEnvironment(config) ?? undefined;
  return engineEvaluatePolicy(
    config,
    toolName,
    args,
    { agent, cwd, activeEnvironment },
    { checkProvenance, isTrustedHost }
  );
}

/** Returns true when toolName matches an ignoredTools pattern (fast-path, silent allow). */
export function isIgnoredTool(toolName: string): boolean {
  return engineIsIgnoredTool(toolName, getConfig());
}

// ── explainPolicy — diagnostic waterfall (heavy I/O, host-only) ─────────────

export interface ExplainStep {
  name: string;
  outcome: 'checked' | 'allow' | 'review' | 'block' | 'skip';
  detail: string;
  isFinal?: boolean;
}

export interface WaterfallTier {
  tier: number;
  label: string;
  status: 'active' | 'missing' | 'env';
  path?: string;
  note?: string;
}

export interface ExplainResult {
  tool: string;
  args: unknown;
  waterfall: WaterfallTier[];
  steps: ExplainStep[];
  decision: 'allow' | 'review' | 'block';
  blockedByLabel?: string;
  matchedToken?: string;
  ruleDescription?: string;
}

function tokenize(toolName: string): string[] {
  return toolName
    .toLowerCase()
    .split(/[_.\-\s]+/)
    .filter(Boolean);
}

function explainExtractShellCommand(
  toolName: string,
  args: unknown,
  toolInspection: Record<string, string>
): { command: string | null; matchingPattern: string | undefined; fieldName: string } {
  const patterns = Object.keys(toolInspection);
  const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
  if (!matchingPattern) return { command: null, matchingPattern: undefined, fieldName: 'command' };
  const fieldPath = toolInspection[matchingPattern];
  const value =
    args && typeof args === 'object' ? (args as Record<string, unknown>)[fieldPath] : undefined;
  return {
    command: typeof value === 'string' ? value : null,
    matchingPattern,
    fieldName: fieldPath,
  };
}

function explainIsSqlTool(toolName: string, toolInspection: Record<string, string>): boolean {
  const patterns = Object.keys(toolInspection);
  const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
  if (!matchingPattern) return false;
  const fieldName = toolInspection[matchingPattern];
  return fieldName === 'sql' || fieldName === 'query';
}

const SQL_DML_KEYWORDS = new Set(['select', 'insert', 'update', 'delete', 'merge', 'upsert']);

export async function explainPolicy(toolName: string, args?: unknown): Promise<ExplainResult> {
  const steps: ExplainStep[] = [];

  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  const projectPath = path.join(process.cwd(), 'node9.config.json');
  const credsPath = path.join(os.homedir(), '.node9', 'credentials.json');

  // ── Waterfall tiers ───────────────────────────────────────────────────────
  const waterfall: WaterfallTier[] = [
    {
      tier: 1,
      label: 'Env vars',
      status: 'env',
      note: process.env.NODE9_MODE ? `NODE9_MODE=${process.env.NODE9_MODE}` : 'not set',
    },
    {
      tier: 2,
      label: 'Cloud policy',
      status: fs.existsSync(credsPath) ? 'active' : 'missing',
      note: fs.existsSync(credsPath)
        ? 'credentials found (not evaluated in explain mode)'
        : 'not connected — run: node9 login',
    },
    {
      tier: 3,
      label: 'Project config',
      status: fs.existsSync(projectPath) ? 'active' : 'missing',
      path: projectPath,
    },
    {
      tier: 4,
      label: 'Global config',
      status: fs.existsSync(globalPath) ? 'active' : 'missing',
      path: globalPath,
    },
    {
      tier: 5,
      label: 'Defaults',
      status: 'active',
      note: 'always active',
    },
  ];

  const config = getConfig();

  // ── 0. DLP Content Scanner ────────────────────────────────────────────────
  const wouldBeIgnored = matchesPattern(toolName, config.policy.ignoredTools);
  if (config.policy.dlp.enabled && (!wouldBeIgnored || config.policy.dlp.scanIgnoredTools)) {
    const argsObjE =
      args && typeof args === 'object' && !Array.isArray(args)
        ? (args as Record<string, unknown>)
        : {};
    const filePathE = String(argsObjE.file_path ?? argsObjE.path ?? argsObjE.filename ?? '');
    const dlpMatch =
      (filePathE ? scanFilePath(filePathE) : null) ?? (args !== undefined ? scanArgs(args) : null);
    if (dlpMatch) {
      steps.push({
        name: 'DLP Content Scanner',
        outcome: dlpMatch.severity === 'block' ? 'block' : 'review',
        detail: `🚨 ${dlpMatch.patternName} detected in ${dlpMatch.fieldPath} — sample: ${dlpMatch.redactedSample}`,
        isFinal: dlpMatch.severity === 'block',
      });
      if (dlpMatch.severity === 'block') {
        return { tool: toolName, args, waterfall, steps, decision: 'block' };
      }
    } else {
      steps.push({
        name: 'DLP Content Scanner',
        outcome: 'checked',
        detail: 'No sensitive credentials detected in args',
      });
    }
  }

  // ── 1. Ignored tools ──────────────────────────────────────────────────────
  if (wouldBeIgnored) {
    steps.push({
      name: 'Ignored tools',
      outcome: 'allow',
      detail: `"${toolName}" matches ignoredTools pattern → fast-path allow`,
      isFinal: true,
    });
    return { tool: toolName, args, waterfall, steps, decision: 'allow' };
  }
  steps.push({
    name: 'Ignored tools',
    outcome: 'checked',
    detail: `"${toolName}" not in ignoredTools list`,
  });

  // ── 2. Smart Rules ────────────────────────────────────────────────────────
  if (config.policy.smartRules.length > 0) {
    const matchedRule = config.policy.smartRules.find(
      (rule) => matchesPattern(toolName, rule.tool) && evaluateSmartConditions(args, rule)
    );
    if (matchedRule) {
      const label = `Smart Rule: ${matchedRule.name ?? matchedRule.tool}`;
      if (matchedRule.verdict === 'allow') {
        steps.push({
          name: 'Smart rules',
          outcome: 'allow',
          detail: `${label} → allow`,
          isFinal: true,
        });
        return { tool: toolName, args, waterfall, steps, decision: 'allow' };
      }
      steps.push({
        name: 'Smart rules',
        outcome: matchedRule.verdict,
        detail: `${label} → ${matchedRule.verdict}${matchedRule.reason ? `: ${matchedRule.reason}` : ''}`,
        isFinal: true,
      });
      return {
        tool: toolName,
        args,
        waterfall,
        steps,
        decision: matchedRule.verdict,
        blockedByLabel: label,
      };
    }
    steps.push({
      name: 'Smart rules',
      outcome: 'checked',
      detail: `No smart rule matched "${toolName}"`,
    });
  } else {
    steps.push({ name: 'Smart rules', outcome: 'skip', detail: 'No smart rules configured' });
  }

  // ── 3. Input parsing ──────────────────────────────────────────────────────
  let allTokens: string[] = [];
  let pathTokens: string[] = [];

  const {
    command: shellCommand,
    matchingPattern,
    fieldName,
  } = explainExtractShellCommand(toolName, args, config.policy.toolInspection);
  if (shellCommand) {
    const analyzed = analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    pathTokens = analyzed.paths;

    steps.push({
      name: 'Input parsing',
      outcome: 'checked',
      detail: `Shell command via toolInspection["${matchingPattern ?? toolName}"] → field "${fieldName}": "${shellCommand}"`,
    });

    // ── 3. Inline exec ────────────────────────────────────────────────────
    const INLINE_EXEC_PATTERN = /^(python3?|bash|sh|zsh|perl|ruby|node|php|lua)\s+(-c|-e|-eval)\s/i;
    if (INLINE_EXEC_PATTERN.test(shellCommand.trim())) {
      steps.push({
        name: 'Inline execution',
        outcome: 'review',
        detail: 'Inline code execution detected (e.g. "bash -c ...") — always requires review',
        isFinal: true,
      });
      return {
        tool: toolName,
        args,
        waterfall,
        steps,
        decision: 'review',
        blockedByLabel: 'Node9 Standard (Inline Execution)',
        ruleDescription:
          'The AI is running code directly from the command line. Review the full script below before allowing it to execute.',
      };
    }
    steps.push({
      name: 'Inline execution',
      outcome: 'checked',
      detail: 'No inline execution pattern detected',
    });

    // ── 3b. AST eval detection ────────────────────────────────────────────
    const evalVerdict = detectDangerousShellExec(shellCommand);
    if (evalVerdict) {
      const label =
        evalVerdict === 'block' ? 'Node9: Eval Remote Execution' : 'Node9: Eval Dynamic Content';
      const detail =
        evalVerdict === 'block'
          ? 'eval of remote download (curl/wget) — near-certain supply-chain attack'
          : 'eval of dynamic content (variable or subshell expansion) — requires approval';
      steps.push({ name: 'AST eval detection', outcome: evalVerdict, detail, isFinal: true });
      return {
        tool: toolName,
        args,
        waterfall,
        steps,
        decision: evalVerdict,
        blockedByLabel: label,
      };
    }
    steps.push({
      name: 'AST eval detection',
      outcome: 'checked',
      detail: 'No dangerous eval detected',
    });

    // ── 4. SQL DML keyword stripping ──────────────────────────────────────
    if (explainIsSqlTool(toolName, config.policy.toolInspection)) {
      allTokens = allTokens.filter((t) => !SQL_DML_KEYWORDS.has(t.toLowerCase()));
      steps.push({
        name: 'SQL token stripping',
        outcome: 'checked',
        detail: 'DML keywords stripped from tokens (SQL safety handled by smart rules)',
      });
    }
  } else {
    allTokens = tokenize(toolName);
    let detail = `No toolInspection match for "${toolName}" — tokens: [${allTokens.join(', ')}]`;
    if (args && typeof args === 'object') {
      const flattenedArgs = JSON.stringify(args).toLowerCase();
      const extraTokens = flattenedArgs.split(/[^a-zA-Z0-9]+/).filter((t) => t.length > 1);
      allTokens.push(...extraTokens);
      const preview = extraTokens.slice(0, 8).join(', ') + (extraTokens.length > 8 ? '…' : '');
      detail += ` + deep scan of args: [${preview}]`;
    }
    steps.push({ name: 'Input parsing', outcome: 'checked', detail });
  }

  // ── 4. Tokens ─────────────────────────────────────────────────────────────
  const uniqueTokens = [...new Set(allTokens)];
  steps.push({
    name: 'Tokens scanned',
    outcome: 'checked',
    detail: `[${uniqueTokens.join(', ')}]`,
  });

  // ── 5. Sandbox paths ──────────────────────────────────────────────────────
  if (pathTokens.length > 0 && config.policy.sandboxPaths.length > 0) {
    const allInSandbox = pathTokens.every((p) => matchesPattern(p, config.policy.sandboxPaths));
    if (allInSandbox) {
      steps.push({
        name: 'Sandbox paths',
        outcome: 'allow',
        detail: `[${pathTokens.join(', ')}] all match sandbox patterns → auto-allow`,
        isFinal: true,
      });
      return { tool: toolName, args, waterfall, steps, decision: 'allow' };
    }
    const unmatched = pathTokens.filter((p) => !matchesPattern(p, config.policy.sandboxPaths));
    steps.push({
      name: 'Sandbox paths',
      outcome: 'checked',
      detail: `[${unmatched.join(', ')}] not in sandbox — not auto-allowed`,
    });
  } else {
    steps.push({
      name: 'Sandbox paths',
      outcome: 'skip',
      detail:
        pathTokens.length === 0 ? 'No path tokens found in input' : 'No sandbox paths configured',
    });
  }

  // ── 6. Dangerous words ────────────────────────────────────────────────────
  let matchedDangerousWord: string | undefined;
  const isDangerous = uniqueTokens.some((token) =>
    config.policy.dangerousWords.some((word) => {
      const w = word.toLowerCase();
      const hit =
        token === w ||
        (() => {
          try {
            return new RegExp(`\\b${w}\\b`, 'i').test(token);
          } catch {
            return false;
          }
        })();
      if (hit && !matchedDangerousWord) matchedDangerousWord = word;
      return hit;
    })
  );
  if (isDangerous) {
    steps.push({
      name: 'Dangerous words',
      outcome: 'review',
      detail: `"${matchedDangerousWord}" found in token list`,
      isFinal: true,
    });
    return {
      tool: toolName,
      args,
      waterfall,
      steps,
      decision: 'review',
      blockedByLabel: `Project/Global Config — dangerous word: "${matchedDangerousWord}"`,
      matchedToken: matchedDangerousWord,
      ruleDescription: `This command contains a flagged keyword ("${matchedDangerousWord}") from your node9 config. Review it before allowing.`,
    };
  }
  steps.push({
    name: 'Dangerous words',
    outcome: 'checked',
    detail: `No dangerous words matched`,
  });

  // ── 8. Strict mode ────────────────────────────────────────────────────────
  if (config.settings.mode === 'strict') {
    steps.push({
      name: 'Strict mode',
      outcome: 'review',
      detail: 'Mode is "strict" — all tools require approval unless explicitly allowed',
      isFinal: true,
    });
    return {
      tool: toolName,
      args,
      waterfall,
      steps,
      decision: 'review',
      blockedByLabel: 'Global Config (Strict Mode Active)',
    };
  }
  steps.push({
    name: 'Strict mode',
    outcome: 'skip',
    detail: `Mode is "${config.settings.mode}" — no catch-all review`,
  });

  return { tool: toolName, args, waterfall, steps, decision: 'allow' };
}
