// @node9/policy-engine — shared policy evaluation engine.
//
// Goal: a pure-function library both node9-proxy and node9Firewall import,
// so DLP patterns, AST shell parsing, smart-rule matching, and shield
// definitions live in exactly one place. No fs/process/os imports at
// runtime — host code passes paths and state in.
//
// Day 2: types only. Implementations stay in node9-proxy until Day 3+.

/** Engine version stamped on audit entries for future drift detection. */
export const ENGINE_VERSION = '0.1.0-alpha.0';

export type { SmartCondition, SmartRule, DlpMatch, RiskMetadata } from './types';
