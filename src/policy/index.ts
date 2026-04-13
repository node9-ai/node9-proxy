// src/policy/index.ts
// Policy engine: smart rule evaluation, dangerous-word checks, shell analysis,
// and the main evaluatePolicy / explainPolicy waterfalls.
import fs from 'fs';
import path from 'path';
import os from 'os';
import pm from 'picomatch';
import { parse } from 'sh-syntax';
import { scanArgs, scanFilePath } from '../dlp';
import { type SmartRule, type Config, getConfig, getActiveEnvironment } from '../config';
import { getCompiledRegex } from '../utils/regex';
import { checkProvenance } from '../utils/provenance.js';
import { analyzePipeChain } from './pipe-chain.js';
import { extractAllSshHosts } from './ssh-parser.js';
import { isTrustedHost } from '../auth/trusted-hosts.js';

// ── Internal helpers ──────────────────────────────────────────────────────────

function tokenize(toolName: string): string[] {
  return toolName
    .toLowerCase()
    .split(/[_.\-\s]+/)
    .filter(Boolean);
}

export function matchesPattern(text: string, patterns: string[] | string): boolean {
  const p = Array.isArray(patterns) ? patterns : [patterns];
  if (p.length === 0) return false;
  const isMatch = pm(p, { nocase: true, dot: true });
  const target = text.toLowerCase();
  const directMatch = isMatch(target);
  if (directMatch) return true;
  const withoutDotSlash = text.replace(/^\.\//, '');
  return isMatch(withoutDotSlash) || isMatch(`./${withoutDotSlash}`);
}

function getNestedValue(obj: unknown, path: string): unknown {
  if (!obj || typeof obj !== 'object') return null;
  return path
    .split('.')
    .reduce<unknown>((prev, curr) => (prev as Record<string, unknown>)?.[curr], obj);
}

// ── SMART RULES EVALUATOR ─────────────────────────────────────────────────────

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

export function evaluateSmartConditions(args: unknown, rule: SmartRule): boolean {
  if (!rule.conditions || rule.conditions.length === 0) return true;
  const mode = rule.conditionMode ?? 'all';

  const results = rule.conditions.map((cond) => {
    const rawVal = getNestedValue(args, cond.field);
    // Normalize whitespace so multi-space SQL doesn't bypass regex checks
    const val =
      rawVal !== null && rawVal !== undefined ? String(rawVal).replace(/\s+/g, ' ').trim() : null;

    switch (cond.op) {
      case 'exists':
        return val !== null && val !== '';
      case 'notExists':
        return val === null || val === '';
      case 'contains':
        return val !== null && cond.value ? val.includes(cond.value) : false;
      case 'notContains':
        return val !== null && cond.value ? !val.includes(cond.value) : true;
      case 'matches': {
        if (val === null || !cond.value) return false;
        const reM = getCompiledRegex(cond.value, cond.flags ?? '');
        if (!reM) return false; // invalid/dangerous pattern → fail closed
        return reM.test(val);
      }
      case 'notMatches': {
        if (!cond.value) return false; // no pattern → fail closed
        if (val === null) return true; // field absent → condition passes (preserve original)
        const reN = getCompiledRegex(cond.value, cond.flags ?? '');
        if (!reN) return false; // invalid/dangerous pattern → fail closed
        return !reN.test(val);
      }
      case 'matchesGlob':
        return val !== null && cond.value ? pm.isMatch(val, cond.value) : false;
      case 'notMatchesGlob':
        // Both absent field AND missing pattern → fail closed.
        // For a security tool, fail-closed is the safer default: an attacker
        // omitting a field must not satisfy a notMatchesGlob allow rule.
        // Rule authors who need "pass when field absent" should add an explicit
        // 'notExists' condition paired with 'notMatchesGlob'.
        return val !== null && cond.value ? !pm.isMatch(val, cond.value) : false;
      default:
        return false;
    }
  });

  return mode === 'any' ? results.some((r) => r) : results.every((r) => r);
}

function extractShellCommand(
  toolName: string,
  args: unknown,
  toolInspection: Record<string, string>
): string | null {
  const patterns = Object.keys(toolInspection);
  const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
  if (!matchingPattern) return null;
  const fieldPath = toolInspection[matchingPattern];
  const value = getNestedValue(args, fieldPath);
  return typeof value === 'string' ? value : null;
}

/** Returns true when a tool's inspected field is SQL (sql or query). */
function isSqlTool(toolName: string, toolInspection: Record<string, string>): boolean {
  const patterns = Object.keys(toolInspection);
  const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
  if (!matchingPattern) return false;
  const fieldName = toolInspection[matchingPattern];
  return fieldName === 'sql' || fieldName === 'query';
}

// SQL DML keywords — safe in a scoped context (WHERE clause present).
// Filtered from tokens so user dangerousWords like "delete"/"update" don't
// re-trigger after the WHERE-clause check has already passed.
const SQL_DML_KEYWORDS = new Set(['select', 'insert', 'update', 'delete', 'merge', 'upsert']);

/**
 * Checks a SQL string for dangerous unscoped mutations.
 * Returns a reason string if dangerous, null if safe.
 */
export function checkDangerousSql(sql: string): string | null {
  const norm = sql.replace(/\s+/g, ' ').trim().toLowerCase();
  const hasWhere = /\bwhere\b/.test(norm);

  if (/^delete\s+from\s+\S+/.test(norm) && !hasWhere)
    return 'DELETE without WHERE — full table wipe';

  if (/^update\s+\S+\s+set\s+/.test(norm) && !hasWhere)
    return 'UPDATE without WHERE — updates every row';

  return null;
}

interface AstNode {
  type: string;
  Args?: { Parts?: { Value?: string }[] }[];
  [key: string]: unknown;
}

async function analyzeShellCommand(
  command: string
): Promise<{ actions: string[]; paths: string[]; allTokens: string[] }> {
  const actions: string[] = [];
  const paths: string[] = [];
  const allTokens: string[] = [];

  const addToken = (token: string) => {
    const lower = token.toLowerCase();
    allTokens.push(lower);
    if (lower.includes('/')) {
      const segments = lower.split('/').filter(Boolean);
      allTokens.push(...segments);
    }
    if (lower.startsWith('-')) {
      allTokens.push(lower.replace(/^-+/, ''));
    }
  };

  try {
    const ast = await parse(command);
    const walk = (node: AstNode | null) => {
      if (!node) return;
      if (node.type === 'CallExpr') {
        const parts = (node.Args || [])
          .map((arg) => {
            return (arg.Parts || []).map((p) => p.Value || '').join('');
          })
          .filter((s: string) => s.length > 0);

        if (parts.length > 0) {
          actions.push(parts[0].toLowerCase());
          parts.forEach((p: string) => addToken(p));
          parts.slice(1).forEach((p: string) => {
            if (!p.startsWith('-')) paths.push(p);
          });
        }
      }
      for (const key in node) {
        if (key === 'Parent') continue;
        const val = node[key];
        if (Array.isArray(val)) {
          val.forEach((child: unknown) => {
            if (child && typeof child === 'object' && 'type' in child) {
              walk(child as AstNode);
            }
          });
        } else if (val && typeof val === 'object' && 'type' in val) {
          walk(val as AstNode);
        }
      }
    };
    walk(ast as unknown as AstNode);
  } catch {
    // Fallback
  }

  if (allTokens.length === 0) {
    const normalized = command.replace(/\\(.)/g, '$1');
    const sanitized = normalized.replace(/["'<>]/g, ' ');
    const segments = sanitized.split(/[|;&]|\$\(|\)|`/);
    segments.forEach((segment) => {
      const tokens = segment.trim().split(/\s+/).filter(Boolean);
      if (tokens.length > 0) {
        const action = tokens[0].toLowerCase();
        if (!actions.includes(action)) actions.push(action);
        tokens.forEach((t) => {
          addToken(t);
          if (t !== tokens[0] && !t.startsWith('-')) {
            if (!paths.includes(t)) paths.push(t);
          }
        });
      }
    });
  }
  return { actions, paths, allTokens };
}

export async function evaluatePolicy(
  toolName: string,
  args?: unknown,
  agent?: string,
  cwd?: string
): Promise<{
  decision: 'allow' | 'review' | 'block';
  blockedByLabel?: string;
  reason?: string;
  matchedField?: string;
  matchedWord?: string;
  tier?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  ruleName?: string;
  /** State predicates from the matched smart rule (only when decision is 'block'). */
  dependsOnStatePredicates?: string[];
  /** Recovery command to suggest when this rule hard-blocks (from SmartRule.recoveryCommand). */
  recoveryCommand?: string;
  /** Plain-English description of what the rule does (from SmartRule.description). */
  ruleDescription?: string;
}> {
  const config = getConfig();

  // 1. Ignored tools (Fast Path) - Always allow these first
  if (matchesPattern(toolName, config.policy.ignoredTools)) return { decision: 'allow' };

  // 2. Smart Rules — raw args matching before tokenization
  if (config.policy.smartRules.length > 0) {
    const matchedRule = config.policy.smartRules.find(
      (rule) => matchesPattern(toolName, rule.tool) && evaluateSmartConditions(args, rule)
    );
    if (matchedRule) {
      if (matchedRule.verdict === 'allow')
        return { decision: 'allow', ruleName: matchedRule.name ?? matchedRule.tool };
      return {
        decision: matchedRule.verdict,
        blockedByLabel: `Smart Rule: ${matchedRule.name ?? matchedRule.tool}`,
        reason: matchedRule.reason,
        tier: 2,
        ruleName: matchedRule.name ?? matchedRule.tool,
        ...((matchedRule.description ?? matchedRule.reason) && {
          ruleDescription: matchedRule.description ?? matchedRule.reason,
        }),
        ...(matchedRule.verdict === 'block' &&
          matchedRule.dependsOnState?.length && {
            dependsOnStatePredicates: matchedRule.dependsOnState,
          }),
        ...(matchedRule.verdict === 'block' &&
          matchedRule.recoveryCommand && {
            recoveryCommand: matchedRule.recoveryCommand,
          }),
      };
    }
  }

  let allTokens: string[] = [];
  let pathTokens: string[] = [];

  // 2. Tokenize the input
  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);
  if (shellCommand) {
    const analyzed = await analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    pathTokens = analyzed.paths;

    // Inline arbitrary code execution is always a review
    const INLINE_EXEC_PATTERN = /^(python3?|bash|sh|zsh|perl|ruby|node|php|lua)\s+(-c|-e|-eval)\s/i;
    if (INLINE_EXEC_PATTERN.test(shellCommand.trim())) {
      return { decision: 'review', blockedByLabel: 'Node9 Standard (Inline Execution)', tier: 3 };
    }

    // ── Pipe-chain exfiltration detection ────────────────────────────────────
    const pipeAnalysis = analyzePipeChain(shellCommand);
    if (
      pipeAnalysis.isPipeline &&
      (pipeAnalysis.risk === 'critical' || pipeAnalysis.risk === 'high')
    ) {
      const sinks = pipeAnalysis.sinkTargets;
      // sinks.length === 0 means no network targets were identified → treat as untrusted
      const allTrusted = sinks.length > 0 && sinks.every(isTrustedHost);

      if (pipeAnalysis.risk === 'critical') {
        // Obfuscated exfil: trusted hosts downgrade block → review; untrusted → block
        if (allTrusted) {
          return {
            decision: 'review',
            blockedByLabel: 'Node9: Pipe-Chain to Trusted Host (obfuscated)',
            reason: `Obfuscated pipe to trusted host(s): ${sinks.join(', ')} — requires approval`,
            tier: 3,
          };
        }
        return {
          decision: 'block',
          blockedByLabel: 'Node9: Pipe-Chain Exfiltration (critical)',
          reason: `Sensitive file piped through obfuscator to network sink: ${pipeAnalysis.sourceFiles.join(', ')} → ${sinks.join(', ')}`,
          tier: 3,
        };
      }

      // high risk: trusted hosts → allow; untrusted → review
      if (allTrusted) {
        return {
          decision: 'allow',
          blockedByLabel: 'Node9: Pipe-Chain to Trusted Host',
          reason: `Sensitive file piped to trusted host(s): ${sinks.join(', ')}`,
          tier: 3,
        };
      }
      return {
        decision: 'review',
        blockedByLabel: 'Node9: Pipe-Chain Exfiltration (high)',
        reason: `Sensitive file piped to network sink: ${pipeAnalysis.sourceFiles.join(', ')} → ${sinks.join(', ')}`,
        tier: 3,
      };
    }

    // ── SSH multi-hop host extraction ─────────────────────────────────────────
    // Runs only for ssh/scp/rsync to extract all involved hosts (including jump hosts).
    // Currently surfaced via tokens for dangerous-word scanning below;
    // deep policy integration (trusted-host check) comes in v1.4.0.
    const firstToken = analyzed.actions[0] ?? '';
    if (['ssh', 'scp', 'rsync'].includes(firstToken)) {
      const rawTokens = shellCommand.trim().split(/\s+/);
      const sshHosts = extractAllSshHosts(rawTokens.slice(1));
      allTokens.push(...sshHosts);
    }

    // ── Binary provenance check ───────────────────────────────────────────────
    // Only check absolute paths (e.g. /tmp/curl). Bare command names (npm, curl)
    // require PATH resolution which varies by environment (nvm, volta, CI toolcache)
    // and causes false positives. The MCP gateway handles provenance for configured
    // upstream servers separately.
    if (firstToken && path.posix.isAbsolute(firstToken)) {
      const prov = checkProvenance(firstToken, cwd);
      if (prov.trustLevel === 'suspect') {
        return {
          decision: config.settings.mode === 'strict' ? 'block' : 'review',
          blockedByLabel: 'Node9: Suspect Binary',
          reason: `Binary "${firstToken}" resolved to ${prov.resolvedPath} — ${prov.reason}`,
          tier: 3,
        };
      }
      if (prov.trustLevel === 'unknown' && config.settings.mode === 'strict') {
        return {
          decision: 'review',
          blockedByLabel: 'Node9: Unknown Binary (strict mode)',
          reason: `Binary "${firstToken}" — ${prov.reason}`,
          tier: 3,
        };
      }
    }

    // Strip DML keywords from tokens so user dangerousWords like "delete"/"update"
    // don't re-flag a SQL query that already passed the smart rules check above.
    if (isSqlTool(toolName, config.policy.toolInspection)) {
      allTokens = allTokens.filter((t) => !SQL_DML_KEYWORDS.has(t.toLowerCase()));
    }
  } else {
    allTokens = tokenize(toolName);

    // Deep scan: if this tool isn't in toolInspection, scan all arg values for dangerous words
    if (args && typeof args === 'object') {
      const flattenedArgs = JSON.stringify(args).toLowerCase();
      const extraTokens = flattenedArgs.split(/[^a-zA-Z0-9]+/).filter((t) => t.length > 1);
      allTokens.push(...extraTokens);
    }
  }

  // ── 3. CONTEXTUAL RISK DOWNGRADE (PRD Section 3 / Phase 3) ──────────────
  // If the human is typing manually, we only block "Nuclear" actions.
  // If the human is typing manually, we only block "Total System Disaster" actions.
  const isManual = agent === 'Terminal';
  if (isManual) {
    const SYSTEM_DISASTER_COMMANDS = ['mkfs', 'shred', 'dd', 'drop', 'truncate', 'purge'];

    const hasSystemDisaster = allTokens.some((t) =>
      SYSTEM_DISASTER_COMMANDS.includes(t.toLowerCase())
    );

    // Catch the most famous disaster: rm -rf /
    const isRootWipe =
      allTokens.includes('rm') && (allTokens.includes('/') || allTokens.includes('/*'));

    if (hasSystemDisaster || isRootWipe) {
      // If it IS a system disaster, return review so the dev gets a
      // "Manual Nuclear Protection" popup as a final safety check.
      return { decision: 'review', blockedByLabel: 'Manual Nuclear Protection', tier: 3 };
    }

    // For everything else (docker, psql, rmdir, delete, rm),
    // we trust the human and auto-allow.
    return { decision: 'allow' };
  }

  // ── 4. Sandbox Check (Safe Zones) ───────────────────────────────────────
  if (pathTokens.length > 0 && config.policy.sandboxPaths.length > 0) {
    const allInSandbox = pathTokens.every((p) => matchesPattern(p, config.policy.sandboxPaths));
    if (allInSandbox) return { decision: 'allow' };
  }

  // ── 5. Dangerous Words Evaluation ───────────────────────────────────────
  let matchedDangerousWord: string | undefined;
  const isDangerous = allTokens.some((token) =>
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
    // Find which specific field contained the dangerous word for the UI
    let matchedField: string | undefined;
    if (matchedDangerousWord && args && typeof args === 'object' && !Array.isArray(args)) {
      const obj = args as Record<string, unknown>;
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
          try {
            if (
              new RegExp(
                `\\b${matchedDangerousWord.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`,
                'i'
              ).test(value)
            ) {
              matchedField = key;
              break;
            }
          } catch {
            /* ignore */
          }
        }
      }
    }
    return {
      decision: 'review',
      blockedByLabel: `Project/Global Config — dangerous word: "${matchedDangerousWord}"`,
      matchedWord: matchedDangerousWord,
      matchedField,
      tier: 6,
    };
  }

  // ── 7. Strict Mode Fallback ─────────────────────────────────────────────
  if (config.settings.mode === 'strict') {
    const envConfig = getActiveEnvironment(config);
    if (envConfig?.requireApproval === false) return { decision: 'allow' };
    return { decision: 'review', blockedByLabel: 'Global Config (Strict Mode Active)', tier: 7 };
  }

  return { decision: 'allow' };
}

// ── explainPolicy ─────────────────────────────────────────────────────────────

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
}

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

  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);
  if (shellCommand) {
    const analyzed = await analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    pathTokens = analyzed.paths;

    const patterns = Object.keys(config.policy.toolInspection);
    const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
    const fieldName = matchingPattern ? config.policy.toolInspection[matchingPattern] : 'command';
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
      };
    }
    steps.push({
      name: 'Inline execution',
      outcome: 'checked',
      detail: 'No inline execution pattern detected',
    });

    // ── 4. SQL DML keyword stripping ──────────────────────────────────────
    // SQL WHERE safety is handled by smart rules above. Here we only strip
    // DML keywords so dangerous-word checks don't re-flag a validated query.
    if (isSqlTool(toolName, config.policy.toolInspection)) {
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

/** Returns true when toolName matches an ignoredTools pattern (fast-path, silent allow). */
export function isIgnoredTool(toolName: string): boolean {
  const config = getConfig();
  return matchesPattern(toolName, config.policy.ignoredTools);
}
