// Types for the shared policy engine.
//
// Day 2 of the v1.16.1 migration: only types live here. Implementations
// stay in node9-proxy until Day 3+. The proxy and SaaS re-export these
// types from the package so both sides see the same shape.
//
// Rule: types only. No runtime values. No imports of fs/path/os/process.

/**
 * A condition inside a SmartRule. The matcher evaluates each condition
 * against the tool call's args, then combines them via conditionMode.
 *
 * Supported ops:
 *   matches / notMatches      — regex (uses `value` + optional `flags`)
 *   contains / notContains    — substring
 *   matchesGlob / notMatchesGlob — picomatch-style glob
 *   exists / notExists        — field presence (no value needed)
 */
export interface SmartCondition {
  field: string;
  op:
    | 'matches'
    | 'notMatches'
    | 'contains'
    | 'notContains'
    | 'exists'
    | 'notExists'
    | 'matchesGlob'
    | 'notMatchesGlob';
  value?: string;
  flags?: string;
}

/**
 * A user-defined or shield-defined rule. The matcher applies it to a
 * tool call; if all (or any) conditions pass, the verdict is emitted.
 *
 * Verdicts:
 *   allow  — permit the call (used for explicit allowlists)
 *   review — send to human approval channel
 *   block  — hard-deny, never executes
 */
export interface SmartRule {
  name?: string;
  tool: string;
  conditions: SmartCondition[];
  conditionMode?: 'all' | 'any';
  verdict: 'allow' | 'review' | 'block';
  reason?: string;
  /**
   * State predicates that must ALL be true for a 'block' verdict to apply.
   * If any predicate is false (or the daemon is unreachable), the block is
   * downgraded to a review. Ignored for 'allow' and 'review' verdicts.
   */
  dependsOnState?: string[];
  /**
   * Shell command to suggest as a recovery action when this rule hard-blocks.
   * Shown to the developer on /dev/tty and passed to the AI as a hint.
   * Example: "npm test"
   */
  recoveryCommand?: string;
  /**
   * Plain-English explanation of what this rule does and why it matters.
   * Shown to the user in the review/block card instead of (or alongside)
   * the raw command. Example: "Force push rewrites shared history and can
   * permanently destroy teammates' work."
   */
  description?: string;
}

/**
 * Result of a DLP scan — either a single match or null. The redactedSample
 * is the only piece of the secret that ever leaves the scanner module;
 * the raw value never appears in audit logs or SaaS payloads.
 */
export interface DlpMatch {
  patternName: string;
  fieldPath: string;
  redactedSample: string;
  severity: 'block' | 'review';
}

/**
 * Risk metadata bundle pre-computed once per tool call and propagated to
 * every approval channel: native popup, browser daemon, cloud/SaaS,
 * Slack, and Mission Control.
 */
export interface RiskMetadata {
  intent: 'EDIT' | 'EXEC';
  tier: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  blockedByLabel: string;
  matchedWord?: string;
  matchedField?: string;
  /** Pre-computed 7-line window with 🛑 marker on the matched line. */
  contextSnippet?: string;
  /** Index of the 🛑 line within the snippet (0-based). */
  contextLineIndex?: number;
  /** basename of file_path (EDIT intent only) */
  editFileName?: string;
  /** full file_path (EDIT intent only) */
  editFilePath?: string;
  /** Tier 2 (Smart Rules) only */
  ruleName?: string;
  /** Human-readable description of the matched smart rule or shield. */
  ruleDescription?: string;
}
