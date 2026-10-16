import { matchArgumentText } from './index';
import type { DlpMatch } from '../types';
import { secretViews, type SecretViewBudget } from './secret-views';

export const ARGUMENT_SCAN_LIMITS = {
  maxDepth: 12,
  maxNodes: 16_384,
  /** Raw text is matched in windows of this size; decoding views use the first window. */
  maxStringCharacters: 100_000,
  /** Windows overlap by this much so a token on a window edge is still seen whole. */
  windowOverlap: 4_096,
  maxSourceBytes: 1_048_576,
  maxJsonCharacters: 10_000,
} as const;

export interface ArgumentInspectionResult {
  match: DlpMatch | null;
  /**
   * `incomplete` when any part of the input was not fully inspected. Reasons
   * starting with `argument-` mean raw text or structure was skipped; reasons
   * starting with `decode-` mean every byte of raw text was matched but the
   * derived decoding views were cut short.
   */
  coverage: 'complete' | 'incomplete';
  reasons: string[];
}

/** Bounded input inspection. Output redaction deliberately retains its own API. */
export function inspectArgumentSecrets(args: unknown): ArgumentInspectionResult {
  const budget: SecretViewBudget = { views: 0, bytes: 0, candidates: 0, reasons: new Set() };
  const ancestors = new Set<object>();
  let nodes = 0;
  let sourceBytes = 0;
  let best: DlpMatch | null = null;
  const accept = (match: DlpMatch | null) => {
    if (match && (!best || (best.severity !== 'block' && match.severity === 'block'))) best = match;
  };
  const visit = (value: unknown, depth: number, fieldPath: string): void => {
    if (++nodes > ARGUMENT_SCAN_LIMITS.maxNodes) {
      budget.reasons.add('argument-nodes');
      return;
    }
    if (value === null || value === undefined) return;
    if (depth > ARGUMENT_SCAN_LIMITS.maxDepth) {
      budget.reasons.add('argument-depth');
      return;
    }
    if (typeof value === 'object') {
      if (ancestors.has(value)) {
        budget.reasons.add('argument-cycle');
        return;
      }
      ancestors.add(value);
      // for-in avoids allocating an unbounded Object.entries array before the cap.
      let index = 0;
      for (const key in value) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
        if (
          nodes >= ARGUMENT_SCAN_LIMITS.maxNodes ||
          sourceBytes >= ARGUMENT_SCAN_LIMITS.maxSourceBytes
        ) {
          budget.reasons.add('argument-budget');
          break;
        }
        // Never expose arbitrary object keys in a finding: keys may themselves
        // contain credentials, terminal escapes, or attacker-controlled prose.
        const childPath = `${fieldPath}[${index++}]`;
        if (!Array.isArray(value)) visit(key, depth + 1, `${childPath}.key`);
        visit((value as Record<string, unknown>)[key], depth + 1, childPath);
      }
      ancestors.delete(value);
      return;
    }
    if (typeof value !== 'string') return;
    let text = value;
    const remaining = ARGUMENT_SCAN_LIMITS.maxSourceBytes - sourceBytes;
    const bytes = Buffer.byteLength(text);
    if (bytes > remaining) {
      budget.reasons.add('argument-bytes');
      text = Buffer.from(text).subarray(0, Math.max(0, remaining)).toString('utf8');
    }
    sourceBytes += Math.min(bytes, Math.max(0, remaining));
    if (!text) return;
    // Every byte of raw text is matched, in overlapping windows. Decoding views
    // are derived from the first window only: an encoded credential deep inside
    // a very large payload is reported as incomplete decoding, not as clean.
    const { maxStringCharacters: window, windowOverlap: overlap } = ARGUMENT_SCAN_LIMITS;
    for (let start = 0; ; start += window - overlap) {
      const chunk = text.slice(start, start + window);
      if (start === 0) {
        for (const view of secretViews(chunk, budget)) {
          const hit = matchArgumentText(view.text, fieldPath, budget);
          if (hit)
            accept(view.transforms.length ? { ...hit, redactedSample: '[encoded secret]' } : hit);
        }
      } else accept(matchArgumentText(chunk, fieldPath, budget));
      if (start + window >= text.length) break;
    }
    if (text.length > window) budget.reasons.add('decode-window');
    const trimmed = text.trim();
    if (
      text.length < ARGUMENT_SCAN_LIMITS.maxJsonCharacters &&
      (trimmed.startsWith('{') || trimmed.startsWith('['))
    ) {
      try {
        visit(JSON.parse(text), depth + 1, fieldPath);
      } catch {
        /* Ordinary strings are not necessarily JSON. */
      }
    }
  };
  visit(args, 0, 'args');
  return {
    match: best,
    coverage: budget.reasons.size ? 'incomplete' : 'complete',
    reasons: [...budget.reasons],
  };
}

/**
 * Existing DLP approval routing. A finding wins. Otherwise raw text or
 * structure that was skipped (`argument-*` reasons) requires review; a cut
 * short decoding budget over fully matched raw text does not interrupt the
 * call, because ordinary documents full of links or hashes exhaust it.
 */
export function scanArgumentSecrets(args: unknown): DlpMatch | null {
  const result = inspectArgumentSecrets(args);
  if (result.match) return result.match;
  return result.reasons.some((reason) => reason.startsWith('argument-'))
    ? {
        patternName: 'Argument inspection incomplete',
        fieldPath: 'args',
        redactedSample: '[uninspected content]',
        severity: 'review',
      }
    : null;
}
