// src/shields/build.ts
// Pure builder for `node9 shield create`: turns inline inputs (block/review
// tools and paths) into a ShieldDefinition. No I/O — fully unit-testable. The
// path-rule generator (pathRules) is the exact primitive `node9 jail add` reuses.

import type { ShieldDefinition, SmartRule } from '@node9/policy-engine';

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
 * Jail a path in BOTH dimensions: a bash `command` regex AND an any-tool
 * `file_path` regex. Returns [] for a path that yields no fragment.
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
    {
      name: `${verdict}-path-${s}-anytool`,
      tool: '*',
      conditions: [{ field: 'file_path', op: 'matches', value }],
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
