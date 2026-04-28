// @node9/policy-engine — shared policy evaluation engine.
//
// Goal: a pure-function library both node9-proxy and node9Firewall import,
// so DLP patterns, AST shell parsing, smart-rule matching, and shield
// definitions live in exactly one place. No fs/process/os imports at
// runtime — host code passes paths and state in.
//
// Day 1: package skeleton only. The first real export comes on Day 2
// (types) and Day 3 (DLP module).

/** Engine version stamped on audit entries for future drift detection. */
export const ENGINE_VERSION = '0.1.0-alpha.0';
