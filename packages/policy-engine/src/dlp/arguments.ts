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
  /** Budget for the first window of every string, so one large field cannot starve the rest. */
  maxSourceBytes: 1_048_576,
  /** Separate budget for the text beyond each string's first window. */
  maxTailBytes: 4_194_304,
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
  let tailBytes = 0;
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
    const { maxStringCharacters: window, windowOverlap: overlap } = ARGUMENT_SCAN_LIMITS;
    // The first window of every string is charged to the source budget; the
    // rest of a long string is charged to a separate tail budget. A padding
    // field therefore cannot exhaust the budget before a later field is read.
    let text = value.slice(0, window);
    const remaining = ARGUMENT_SCAN_LIMITS.maxSourceBytes - sourceBytes;
    const bytes = Buffer.byteLength(text);
    const truncated = bytes > remaining;
    if (truncated) {
      budget.reasons.add('argument-bytes');
      text = Buffer.from(text).subarray(0, Math.max(0, remaining)).toString('utf8');
    }
    sourceBytes += Math.min(bytes, Math.max(0, remaining));
    if (!text) return;
    for (const view of secretViews(text, budget)) {
      const hit = matchArgumentText(view.text, fieldPath, budget);
      if (hit)
        accept(view.transforms.length ? { ...hit, redactedSample: '[encoded secret]' } : hit);
    }
    if (!truncated && value.length > window) {
      // Raw text beyond the first window is matched in overlapping windows.
      // Decoding views come from the first window only.
      budget.reasons.add('decode-window');
      for (let start = window - overlap; start < value.length; start += window - overlap) {
        const chunk = value.slice(start, start + window);
        const chunkBytes = Buffer.byteLength(chunk);
        if (tailBytes + chunkBytes > ARGUMENT_SCAN_LIMITS.maxTailBytes) {
          budget.reasons.add('argument-string');
          break;
        }
        tailBytes += chunkBytes;
        accept(matchArgumentText(chunk, fieldPath, budget));
        if (start + window >= value.length) break;
      }
    }
    const trimmed = text.trim();
    if (
      value.length < ARGUMENT_SCAN_LIMITS.maxJsonCharacters &&
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
