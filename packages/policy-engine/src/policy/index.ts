// Stateless policy evaluator. The host passes config, args, optional
// context (agent, cwd, active environment) and an optional hook bag for
// I/O-bound checks (binary provenance, trusted-host lookup).
//
// Engine purity: no fs/path/os/process imports here. Anything that needs
// to touch the host system arrives via the hooks parameter.

import type { SmartRule } from '../types';
import { scanArgs } from '../dlp';
import { detectDangerousShellExec, analyzeShellCommand, type ShellCommandAnalysis } from '../shell';
import { matchesPattern, evaluateSmartConditions, getNestedValue } from '../rules';
import { analyzePipeChain } from './pipe-chain';
import { extractAllSshHosts } from './ssh-parser';

// ── Public types ──────────────────────────────────────────────────────────────

export interface PolicyConfig {
  policy: {
    sandboxPaths: string[];
    dangerousWords: string[];
    ignoredTools: string[];
    toolInspection: Record<string, string>;
    smartRules: SmartRule[];
    dlp: { enabled: boolean; scanIgnoredTools: boolean };
  };
  settings: {
    mode: string;
  };
}

export interface PolicyContext {
  /** "Terminal" disables most blocks (manual user typing). */
  agent?: string;
  /** Working directory passed through to provenance hook. */
  cwd?: string;
  /**
   * Resolved environment block from getActiveEnvironment() in the host.
   * If `requireApproval === false`, strict mode skips the catch-all review.
   */
  activeEnvironment?: { requireApproval?: boolean };
}

export type ProvenanceTrust = 'system' | 'managed' | 'user' | 'suspect' | 'unknown';

export interface ProvenanceLookup {
  resolvedPath: string;
  trustLevel: ProvenanceTrust;
  reason: string;
}

export interface PolicyHostHooks {
  /** Resolves an absolute binary path to a trust classification. */
  checkProvenance?: (binary: string, cwd?: string) => ProvenanceLookup;
  /** Returns true if the host is on the user's trusted-hosts allowlist. */
  isTrustedHost?: (host: string) => boolean;
}

export interface PolicyVerdict {
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
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function tokenize(toolName: string): string[] {
  return toolName
    .toLowerCase()
    .split(/[_.\-\s]+/)
    .filter(Boolean);
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

// ── Public evaluator ──────────────────────────────────────────────────────────

/**
 * Stateless policy evaluation. Same waterfall as the original
 * proxy/src/policy/index.ts:evaluatePolicy, but config + context + I/O
 * hooks come in as parameters so this function works in any host.
 *
 * Returns 'allow' for ignored tools, the matched smart-rule verdict,
 * inline-execution review, eval-detection verdict, pipe-chain verdict,
 * provenance verdict, sandbox allow, dangerous-word review, or strict-mode
 * fallback. See the design doc for the full tier table.
 */
export async function evaluatePolicy(
  config: PolicyConfig,
  toolName: string,
  args?: unknown,
  context: PolicyContext = {},
  hooks: PolicyHostHooks = {}
): Promise<PolicyVerdict> {
  const { agent, cwd, activeEnvironment } = context;
  const { checkProvenance, isTrustedHost } = hooks;

  // 0. DLP Content Scanner — runs before ignoredTools fast path so credentials
  // in "safe" tools (ls, grep, cat) are always caught when scanIgnoredTools is on.
  // Uses scanArgs only (not scanFilePath): sensitive-path access is already covered
  // by smart rules; this tier catches secret content (AWS keys, tokens) in arg values.
  const wouldBeIgnored = matchesPattern(toolName, config.policy.ignoredTools);
  if (config.policy.dlp.enabled && (!wouldBeIgnored || config.policy.dlp.scanIgnoredTools)) {
    const dlpMatch = args !== undefined ? scanArgs(args) : null;
    if (dlpMatch) {
      return {
        decision: dlpMatch.severity,
        blockedByLabel: `DLP: ${dlpMatch.patternName}`,
        reason: `${dlpMatch.patternName} detected in ${dlpMatch.fieldPath}`,
      };
    }
  }

  // 1. Ignored tools (Fast Path) - Always allow these first
  if (wouldBeIgnored) return { decision: 'allow' };

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

  // 3. Tokenize the input
  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);
  if (shellCommand) {
    const analyzed: ShellCommandAnalysis = analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    pathTokens = analyzed.paths;

    // Inline arbitrary code execution is always a review
    const INLINE_EXEC_PATTERN = /^(python3?|bash|sh|zsh|perl|ruby|node|php|lua)\s+(-c|-e|-eval)\s/i;
    if (INLINE_EXEC_PATTERN.test(shellCommand.trim())) {
      return {
        decision: 'review',
        blockedByLabel: 'Node9 Standard (Inline Execution)',
        ruleDescription:
          'The AI is running code directly from the command line. Review the full script below before allowing it to execute.',
        tier: 3,
      };
    }

    // AST-based eval detection — structurally accurate, not fooled by string content
    const evalVerdict = detectDangerousShellExec(shellCommand);
    if (evalVerdict === 'block') {
      return {
        decision: 'block',
        blockedByLabel: 'Node9: Eval Remote Execution',
        reason: 'eval of remote download (curl/wget) is a near-certain supply-chain attack',
        ruleDescription:
          'The AI is downloading a script from the internet and running it immediately without inspection. This is a common way malware gets installed.',
        tier: 3,
      };
    }
    if (evalVerdict === 'review') {
      return {
        decision: 'review',
        blockedByLabel: 'Node9: Eval Dynamic Content',
        reason: 'eval of dynamic content (variable or subshell expansion) requires approval',
        ruleDescription:
          'The AI is running a command that includes a variable or subshell expansion. The actual command executed at runtime may differ from what is shown here.',
        tier: 3,
      };
    }

    // ── Pipe-chain exfiltration detection ────────────────────────────────────
    const pipeAnalysis = analyzePipeChain(shellCommand);
    if (
      pipeAnalysis.isPipeline &&
      (pipeAnalysis.risk === 'critical' || pipeAnalysis.risk === 'high')
    ) {
      const sinks = pipeAnalysis.sinkTargets;
      // sinks.length === 0 means no network targets were identified → treat as untrusted
      const allTrusted =
        sinks.length > 0 && sinks.every((host) => (isTrustedHost ? isTrustedHost(host) : false));

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
    // Currently surfaced via tokens for dangerous-word scanning below.
    const firstToken = analyzed.actions[0] ?? '';
    if (['ssh', 'scp', 'rsync'].includes(firstToken)) {
      const rawTokens = shellCommand.trim().split(/\s+/);
      const sshHosts = extractAllSshHosts(rawTokens.slice(1));
      allTokens.push(...sshHosts);
    }

    // ── Binary provenance check ───────────────────────────────────────────────
    // Only check absolute paths (e.g. /tmp/curl). Bare command names (npm, curl)
    // require PATH resolution which varies by environment (nvm, volta, CI toolcache)
    // and causes false positives. Skips entirely when no provenance hook is wired.
    if (firstToken && firstToken.startsWith('/') && checkProvenance) {
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

  // ── 4. CONTEXTUAL RISK DOWNGRADE ────────────────────────────────────────
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

  // ── 5. Sandbox Check (Safe Zones) ───────────────────────────────────────
  if (pathTokens.length > 0 && config.policy.sandboxPaths.length > 0) {
    const allInSandbox = pathTokens.every((p) => matchesPattern(p, config.policy.sandboxPaths));
    if (allInSandbox) return { decision: 'allow' };
  }

  // ── 6. Dangerous Words Evaluation ───────────────────────────────────────
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
      ruleDescription: `This command contains a flagged keyword ("${matchedDangerousWord}") from your node9 config. Review it before allowing.`,
      tier: 6,
    };
  }

  // ── 7. Strict Mode Fallback ─────────────────────────────────────────────
  if (config.settings.mode === 'strict') {
    if (activeEnvironment?.requireApproval === false) return { decision: 'allow' };
    return { decision: 'review', blockedByLabel: 'Global Config (Strict Mode Active)', tier: 7 };
  }

  return { decision: 'allow' };
}

/** Returns true when toolName matches the config's ignoredTools list. */
export function isIgnoredTool(toolName: string, config: PolicyConfig): boolean {
  return matchesPattern(toolName, config.policy.ignoredTools);
}
