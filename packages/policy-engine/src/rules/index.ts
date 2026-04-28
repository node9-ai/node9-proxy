// Smart-rule matcher. Pure functions: tool-name pattern matching, nested
// field lookup, and condition evaluation against args.
//
// Inputs come in as plain JS values; outputs are booleans. Hosts pass the
// SmartRule shape they already validated with zod — this layer doesn't
// re-validate, it only evaluates.

import pm from 'picomatch';
import type { SmartRule } from '../types';
import { normalizeCommandForPolicy } from '../shell';
import { getCompiledRegex } from '../utils/regex';

/**
 * Glob match a tool name against one pattern or a list, with case-insensitive
 * matching and a leading-`./` tolerance: `./bin/foo` matches `bin/foo` and
 * vice-versa so authoring is forgiving.
 */
export function matchesPattern(text: string, patterns: string[] | string): boolean {
  const p = Array.isArray(patterns) ? patterns : [patterns];
  if (p.length === 0) return false;
  const isMatch = pm(p, { nocase: true, dot: true });
  const target = text.toLowerCase();
  const directMatch = isMatch(target);
  if (directMatch) return true;
  const withoutDotSlash = text.replace(/^\.\//, '');
  return isMatch(withoutDotSlash) || isMatch(`./${withoutDotSlash}`);
}

/**
 * Reads `obj.a.b.c` style nested keys. Returns null when any segment is
 * missing or the parent isn't an object.
 */
export function getNestedValue(obj: unknown, path: string): unknown {
  if (!obj || typeof obj !== 'object') return null;
  return path
    .split('.')
    .reduce<unknown>((prev, curr) => (prev as Record<string, unknown>)?.[curr], obj);
}

/**
 * Evaluates a SmartRule's conditions against an args object.
 * Returns true if the rule matches under its conditionMode (default: 'all').
 *
 * The 'command' field gets normalizeCommandForPolicy applied so quoted
 * message text (commit messages, PR bodies) doesn't accidentally match.
 *
 * Fail-closed semantics: invalid regex patterns return false; missing fields
 * + notMatchesGlob return false (an attacker cannot satisfy an allow-rule
 * by omitting a field).
 */
export function evaluateSmartConditions(args: unknown, rule: SmartRule): boolean {
  if (!rule.conditions || rule.conditions.length === 0) return true;
  const mode = rule.conditionMode ?? 'all';

  const results = rule.conditions.map((cond) => {
    const rawVal = getNestedValue(args, cond.field);
    // Normalize whitespace so multi-space SQL doesn't bypass regex checks
    const normalized =
      rawVal !== null && rawVal !== undefined ? String(rawVal).replace(/\s+/g, ' ').trim() : null;
    // For command fields, strip quoted string arguments (commit messages, inline
    // scripts) so patterns match only actual shell commands, not their text args.
    const val =
      cond.field === 'command' && normalized !== null
        ? normalizeCommandForPolicy(normalized)
        : normalized;

    switch (cond.op) {
      case 'exists':
        return val !== null && val !== '';
      case 'notExists':
        return val === null || val === '';
      case 'contains':
        return val !== null && cond.value ? val.includes(cond.value) : false;
      case 'notContains':
        return val !== null && cond.value ? !val.includes(cond.value) : true;
      case 'matches': {
        if (val === null || !cond.value) return false;
        const reM = getCompiledRegex(cond.value, cond.flags ?? '');
        if (!reM) return false; // invalid/dangerous pattern → fail closed
        return reM.test(val);
      }
      case 'notMatches': {
        if (!cond.value) return false; // no pattern → fail closed
        if (val === null) return true; // field absent → condition passes (preserve original)
        const reN = getCompiledRegex(cond.value, cond.flags ?? '');
        if (!reN) return false; // invalid/dangerous pattern → fail closed
        return !reN.test(val);
      }
      case 'matchesGlob':
        return val !== null && cond.value ? pm.isMatch(val, cond.value) : false;
      case 'notMatchesGlob':
        // Both absent field AND missing pattern → fail closed.
        // For a security tool, fail-closed is the safer default: an attacker
        // omitting a field must not satisfy a notMatchesGlob allow rule.
        // Rule authors who need "pass when field absent" should add an explicit
        // 'notExists' condition paired with 'notMatchesGlob'.
        return val !== null && cond.value ? !pm.isMatch(val, cond.value) : false;
      default:
        return false;
    }
  });

  return mode === 'any' ? results.some((r) => r) : results.every((r) => r);
}
