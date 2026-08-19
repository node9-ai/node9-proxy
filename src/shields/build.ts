// src/shields/build.ts
// Pure builder for `node9 shield create`: turns inline inputs (block/review
// tools and paths) into a ShieldDefinition. No I/O — fully unit-testable. The
// path-rule generator (pathRules) is the exact primitive `node9 jail add` reuses.

import type { ShieldDefinition, SmartRule } from '@node9/policy-engine';
import { getCompiledRegex } from '@node9/policy-engine';

type Verdict = 'block' | 'review';

/** Escape a literal string for safe embedding in a RegExp source. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** kebab-case slug for rule names: lowercase, runs of non-alphanumerics → '-'. */
export function slug(s: string): string {
  return (
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'rule'
  );
}

// Path-boundary char classes, written as RegExp *source* (not JS escapes):
//   B   — a segment boundary other than start/end: whitespace or a slash
//   SEP — a separator BETWEEN path segments: forward- or back-slash
const B = '[\\s/\\\\]';
const SEP = '[/\\\\]';

/**
 * Turn a path like `~/.gmail-mcp` or `~/.aws/credentials` into a RegExp source
 * that matches the path at a segment boundary in either / or \ form, anchored so
 * it does NOT prefix-match (`~/.gmail-mcphost` must not match `~/.gmail-mcp`).
 * Strips `~`, `$HOME`, and an absolute `/home|/Users/<user>` prefix down to the
 * distinctive tail so it matches whether the path is written tilde- or absolute.
 * Returns '' for a path with no usable tail (e.g. bare `~`).
 */
export function pathToRegexFragment(rawPath: string): string {
  const tail = rawPath
    .trim()
    .replace(/^~[\\/]?/, '')
    .replace(/^\$\{?HOME\}?[\\/]?/, '')
    .replace(/^\/(?:home|Users)\/[^\\/]+[\\/]?/, '')
    // Windows twin of the rule above: C:\Users\<name>\... (any drive letter,
    // either slash). Without this the fragment keeps drive+username — longer
    // (it blew the engine's regex length cap and died silently) and less
    // portable (~/.aws and C:\Users\x\.aws should denote the same jail).
    .replace(/^[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/]?/, '')
    .replace(/^[\\/]+/, '')
    .replace(/[\\/]+$/, '');
  const segments = tail
    .split(/[\\/]+/)
    .filter(Boolean)
    .map(escapeRegex);
  if (segments.length === 0) return '';
  return `(^|${B})${segments.join(SEP)}(${B}|$)`;
}

/** Block/review an entire tool by name (empty conditions = match-all). */
export function toolRule(tool: string, verdict: Verdict, reason?: string): SmartRule {
  return {
    name: `${verdict}-${slug(tool)}`,
    tool,
    conditions: [],
    verdict,
    reason: reason ?? `${tool} is restricted by this shield`,
  };
}

/**
 * Test a candidate string against a jailable path using the SAME regex the
 * shield rules embed (task #20: the orchestrator's file-tool guard must never
 * disagree with the engine about what counts as a jailed path — one matcher).
 * Returns false for a path that yields no fragment.
 */
export function pathMatchesFragment(candidate: string, rawPath: string): boolean {
  const value = pathToRegexFragment(rawPath);
  if (!value || !candidate) return false;
  // Compile through the ENGINE's pipeline — cap, ReDoS analysis and all. This
  // guard once used a raw `new RegExp(value)` while the engine used its capped
  // getCompiledRegex, so on a long (Windows) fragment the guard said "jailed"
  // while the engine said "no match" and allowed: the two arbiters disagreed,
  // which is the exact split task #20 forbade. One compiler, one answer.
  const re = getCompiledRegex(value);
  if (!re) return false; // engine would no-match → the guard must agree
  return re.test(candidate);
}

/**
 * Jail a path in BOTH dimensions: a bash `command` regex AND any-tool rules
 * for the arg fields file tools actually send. Returns [] for a path that
 * yields no fragment.
 *
 * Task #20: the engine resolves condition fields by exact name (a missing
 * field FAILS the condition), so a single `file_path` rule can never match
 * `Grep {pattern, path}` or `Glob {pattern}` — the jail was engine-invisible
 * to every file tool except Read. One rule per field, OR-ed at the rule level.
 */
export function pathRules(rawPath: string, verdict: Verdict, reason?: string): SmartRule[] {
  const value = pathToRegexFragment(rawPath);
  if (!value) return [];
  const why = reason ?? `Accessing ${rawPath} is restricted by this shield`;
  const s = slug(rawPath);
  return [
    {
      name: `${verdict}-path-${s}-bash`,
      tool: 'bash',
      conditions: [{ field: 'command', op: 'matches', value }],
      verdict,
      reason: why,
    },
    // Keep the historical `-anytool` name for the file_path rule: the
    // rule→shield attribution maps (Report SHIELDS panel) key on rule names.
    {
      name: `${verdict}-path-${s}-anytool`,
      tool: '*',
      conditions: [{ field: 'file_path', op: 'matches', value }],
      verdict,
      reason: why,
    },
    {
      name: `${verdict}-path-${s}-anytool-path`,
      tool: '*',
      conditions: [{ field: 'path', op: 'matches', value }],
      verdict,
      reason: why,
    },
    {
      name: `${verdict}-path-${s}-anytool-pattern`,
      tool: '*',
      conditions: [{ field: 'pattern', op: 'matches', value }],
      verdict,
      reason: why,
    },
  ];
}

export interface BuildShieldInput {
  name: string;
  description?: string;
  aliases?: string[];
  blockTools?: string[];
  reviewTools?: string[];
  blockPaths?: string[];
  reviewPaths?: string[];
}

/** Assemble a complete ShieldDefinition from inline inputs. Pure — no I/O. */
export function buildShield(input: BuildShieldInput): ShieldDefinition {
  const smartRules: SmartRule[] = [
    ...(input.blockTools ?? []).map((t) => toolRule(t, 'block')),
    ...(input.reviewTools ?? []).map((t) => toolRule(t, 'review')),
    ...(input.blockPaths ?? []).flatMap((p) => pathRules(p, 'block')),
    ...(input.reviewPaths ?? []).flatMap((p) => pathRules(p, 'review')),
  ];
  return {
    name: input.name,
    description:
      input.description ?? `Custom shield "${input.name}" created with node9 shield create`,
    aliases: input.aliases ?? [],
    smartRules,
    dangerousWords: [],
  };
}
