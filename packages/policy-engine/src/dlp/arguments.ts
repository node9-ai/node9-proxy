import { matchArgumentBatch, matchArgumentText } from './index';
import { isInvisibleChar } from './normalize';
import type { DlpMatch } from '../types';
import {
  newSecretViewBudget,
  secretViews,
  SECRET_VIEW_LIMITS,
  type SecretView,
} from './secret-views';

export const ARGUMENT_SCAN_LIMITS = {
  maxDepth: 12,
  maxNodes: 16_384,
  /** Text is matched and decoded in windows of this size. */
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
   * `incomplete` when any part of the input was not fully inspected: raw text
   * or structure skipped (`argument-*`), a decoding layer past the nested
   * limits (`decode-nested`), a flood of joinable hostname labels
   * (`decode-labels`), or the recovery-phrase hash budget (`mnemonic-budget`).
   * Every reason requires review; none is a documented allow.
   */
  coverage: 'complete' | 'incomplete';
  reasons: string[];
}

/** Characters of every supported encoding (base64/url, hex forms, percent, base32, DNS labels). */
const RUN_CHAR = /[A-Za-z0-9+/=_%\\.-]/;
/** Part of an encoded run: an encoding character, or an invisible the decoder removes. */
const runChar = (value: string, index: number): boolean => {
  const char = value[index] ?? '';
  return RUN_CHAR.test(char) || (char !== '' && isInvisibleChar(char));
};

/** Decoded fragments grouped for one matcher pass each. */
function batches(views: SecretView[]): string[][] {
  const out: string[][] = [];
  let current: string[] = [];
  let size = 0;
  for (const { text } of views) {
    if (current.length && size + text.length > SECRET_VIEW_LIMITS.batchCharacters) {
      out.push(current);
      current = [];
      size = 0;
    }
    current.push(text);
    size += text.length;
  }
  if (current.length) out.push(current);
  return out;
}

/** Bounded input inspection. Output redaction deliberately retains its own API. */
export function inspectArgumentSecrets(args: unknown): ArgumentInspectionResult {
  const budget = newSecretViewBudget();
  const ancestors = new Set<object>();
  let nodes = 0;
  let sourceBytes = 0;
  let tailBytes = 0;
  let best: DlpMatch | null = null;
  const blocked = (): boolean => best?.severity === 'block';
  const accept = (match: DlpMatch | null) => {
    if (match && (!best || (best.severity !== 'block' && match.severity === 'block'))) best = match;
  };
  // Every decoded view of a segment, in batches; a block ends the work, and a
  // finding wins over any incomplete coverage.
  const decodeSegment = (segment: string, fieldPath: string): void => {
    for (const batch of batches(secretViews(segment, budget))) {
      accept(matchArgumentBatch(batch, fieldPath, budget));
      if (blocked()) return;
    }
  };
  const visit = (value: unknown, depth: number, fieldPath: string): void => {
    if (blocked()) return;
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
    // Raw text: the first window, then overlapping windows within the tail budget.
    accept(matchArgumentText(text, fieldPath, budget));
    let scannedEnd = text.length;
    if (!truncated && value.length > window) {
      for (let start = window - overlap; start < value.length; start += window - overlap) {
        if (blocked()) return;
        const chunk = value.slice(start, start + window);
        const chunkBytes = Buffer.byteLength(chunk);
        if (tailBytes + chunkBytes > ARGUMENT_SCAN_LIMITS.maxTailBytes) {
          budget.reasons.add('argument-string');
          break;
        }
        tailBytes += chunkBytes;
        accept(matchArgumentText(chunk, fieldPath, budget));
        scannedEnd = start + chunk.length;
        if (start + window >= value.length) break;
      }
    }
    // Decoded views of the same text, in contiguous segments of about a
    // window. A segment that would end inside an encoded run runs on to the
    // run's end and the next one starts there: no run is split or decoded
    // twice, and decoding stays linear (fw#338 review 3: a 9 KB base64 run
    // across a window edge was missed while coverage said complete).
    for (let start = 0; start < scannedEnd && !blocked();) {
      let end = Math.min(start + window, scannedEnd);
      while (end < scannedEnd && runChar(value, end - 1) && runChar(value, end)) end++;
      decodeSegment(value.slice(start, end), fieldPath);
      start = end;
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
 * Existing DLP approval routing. A finding wins. Otherwise any part of the
 * input that was not fully inspected requires review: there is no limit an
 * attacker can reach that ends in a clean result.
 */
export function scanArgumentSecrets(args: unknown): DlpMatch | null {
  const result = inspectArgumentSecrets(args);
  if (result.match) return result.match;
  return result.coverage === 'incomplete'
    ? {
        patternName: 'Argument inspection incomplete',
        fieldPath: 'args',
        redactedSample: '[uninspected content]',
        severity: 'review',
      }
    : null;
}
