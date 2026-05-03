// @node9/policy-engine — shared policy evaluation engine.
//
// Goal: a pure-function library both node9-proxy and node9Firewall import,
// so DLP patterns, AST shell parsing, smart-rule matching, and shield
// definitions live in exactly one place. No fs/process/os imports at
// runtime — host code passes paths and state in.
//
// Day 3: DLP module moved here. Path-resolving I/O lives in the proxy's
// scanFilePath wrapper since that's filesystem access.

/** Engine version stamped on audit entries for future drift detection. */
export const ENGINE_VERSION = '1.2.0';

export type { SmartCondition, SmartRule, DlpMatch, RiskMetadata } from './types';

// DLP — pure scanners. Path-resolving I/O wraps matchSensitivePath in the proxy.
export {
  DLP_PATTERNS,
  scanArgs,
  scanText,
  redactText,
  matchSensitivePath,
  sensitivePathMatch,
  SENSITIVE_PATH_REGEXES,
} from './dlp';

// Shell — AST-based detectors (mvdan-sh). Pure: input is a string, output is a verdict.
export type { ShellCommandAnalysis } from './shell';
export {
  normalizeCommandForPolicy,
  detectDangerousShellExec,
  detectDangerousEval,
  analyzeShellCommand,
} from './shell';

// Policy — pure shell sub-helpers (pipe-chain, ssh, flag tables) + stateless evaluator.
export type { PipeChainAnalysis } from './policy/pipe-chain';
export { analyzePipeChain } from './policy/pipe-chain';
export { extractAllSshHosts, parseAllSshHostsFromCommand } from './policy/ssh-parser';
export {
  FLAGS_WITH_VALUES,
  extractPositionalArgs,
  extractNetworkTargets,
} from './policy/flag-tables';
export type {
  PolicyConfig,
  PolicyContext,
  PolicyHostHooks,
  PolicyVerdict,
  ProvenanceLookup,
  ProvenanceTrust,
} from './policy';
export { evaluatePolicy, isIgnoredTool, checkDangerousSql } from './policy';

// Smart rules — tool-name pattern match + condition evaluator.
export { matchesPattern, getNestedValue, evaluateSmartConditions } from './rules';

// Regex utilities — ReDoS-safe validation + LRU-cached compilation.
export { validateRegex, getCompiledRegex } from './utils/regex';

// Shields — 11 builtin definitions + pure validators (no fs).
export type { ShieldDefinition, ShieldVerdict, ShieldOverrides } from './shields';
export {
  BUILTIN_SHIELDS,
  isShieldVerdict,
  validateShieldDefinition,
  validateOverrides,
} from './shields';

// Loop detection — pure sliding-window math; host wraps with persistence.
export type { ToolCallRecord, LoopWindowEvaluation } from './loop';
export { LOOP_MAX_RECORDS, computeArgsHash, evaluateLoopWindow } from './loop';

// Severity classification & risk scoring — single source of truth for
// "how bad is this?" used by both proxy `scan --narrative` and the SaaS
// /report aggregation endpoint.
export type { Severity, ScoreTier, AuditEntryForClassify } from './severity';
export {
  classifyRuleSeverity,
  narrativeRuleLabel,
  classifyAuditEntry,
  computeSecurityScore,
} from './severity';

// Blast summarization — per-machine "what's reachable on disk" reduced to
// a network-safe summary the proxy pushes to the SaaS on every policy-sync
// tick. Pure: host code does the I/O, engine sanitises + sorts.
export type { BlastFinding, BlastEnvFinding, BlastResult, BlastSummary } from './blast';
export { summarizeBlast, truncateBlastPath } from './blast';
