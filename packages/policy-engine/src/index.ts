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
export const ENGINE_VERSION = '0.1.0-alpha.0';

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
