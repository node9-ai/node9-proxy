// src/cli/render/explain-display.ts
//
// Render-boundary helpers for `node9 explain`.
//
// explain prints user-supplied text (the command, the tool name, tokens and
// field values echoed in step details). Two things must hold for every such
// string before it reaches the terminal or a parser:
//   1. A secret in it is redacted, with the same DLP patterns the hook uses.
//   2. It stays on one visible line: a newline, CR, terminal escape or bidi
//      override cannot forge a `Decision:` line or rewrite what was printed.
//
// The explainPolicy() API keeps returning raw data; only the CLI output is
// sanitized here. Pure: no I/O.

import { redactText } from '@node9/policy-engine';
import type { ExplainResult } from '../../policy';

// C0 controls (tab included), DEL, C1 controls, the Arabic letter mark, LRM/RLM,
// the Unicode line/paragraph separators and the bidi embedding/override/isolate
// characters.
const UNSAFE_CHARS =
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

const VISIBLE_ESCAPES: Record<string, string> = {
  '\n': '\\n',
  '\r': '\\r',
  '\t': '\\t',
  '\x1b': '\\x1b',
};

function toVisibleEscape(c: string): string {
  return VISIBLE_ESCAPES[c] ?? `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;
}

const redact = (s: string): string => redactText(s).result;
const escapeUnsafe = (s: string): string => s.replace(UNSAFE_CHARS, toVisibleEscape);

/** Redact secrets, then make control and bidi characters visible. */
export function displaySafe(text: string): string {
  return escapeUnsafe(redact(text));
}

export const INPUT_PREVIEW_MAX = 80;

/** The `Input:` line. Redacted on the whole string first, so the cut never
 *  leaves part of a secret readable; cut by code points, so an emoji is never
 *  split; escaped last, so a visible escape is never split. With control
 *  characters in the input the escaped line can exceed INPUT_PREVIEW_MAX. */
export function inputPreview(raw: string): string {
  const redacted = redact(raw);
  const points = Array.from(redacted);
  const cut =
    points.length > INPUT_PREVIEW_MAX
      ? points.slice(0, INPUT_PREVIEW_MAX - 3).join('') + '…'
      : redacted;
  return escapeUnsafe(cut);
}

// What JSON.stringify leaves raw from UNSAFE_CHARS: it already escapes C0.
const JSON_RAW_UNSAFE = /[\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/** JSON.stringify, with the characters it leaves raw (DEL, C1, line
 *  separators, bidi) written as \uXXXX. Still valid JSON and JSON.parse
 *  returns the same strings, but a human reading the document in a terminal
 *  cannot be shown reordered or rewritten text. */
export function toSafeJson(doc: unknown): string {
  return JSON.stringify(doc, null, 2).replace(
    JSON_RAW_UNSAFE,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`
  );
}

/**
 * Wire schema for `node9 explain --json`. schemaVersion is locked at 1; a
 * breaking rename or removal must bump it. A document without `decision` is
 * a failure: errors are printed as { schemaVersion, error } with exit code 1.
 *
 * String fields here are only redacted: toSafeJson() handles the escaping.
 */
export interface ExplainJson {
  schemaVersion: 1;
  tool: string;
  input: string | null;
  decision: ExplainResult['decision'];
  reason: string | null;
  ruleDescription: string | null;
  steps: Array<{
    name: string;
    outcome: ExplainResult['steps'][number]['outcome'];
    detail: string;
    final: boolean;
  }>;
  waterfall: ExplainResult['waterfall'];
}

export interface ExplainJsonError {
  schemaVersion: 1;
  error: string;
}

export function buildExplainJson(result: ExplainResult, rawInput: string | undefined): ExplainJson {
  return {
    schemaVersion: 1,
    tool: redact(result.tool),
    input: rawInput === undefined ? null : redact(rawInput),
    decision: result.decision,
    reason: result.blockedByLabel ? redact(result.blockedByLabel) : null,
    ruleDescription: result.ruleDescription ? redact(result.ruleDescription) : null,
    steps: result.steps.map((s) => ({
      name: redact(s.name),
      outcome: s.outcome,
      detail: redact(s.detail),
      final: s.isFinal === true,
    })),
    waterfall: result.waterfall.map((t) => ({
      ...t,
      ...(t.path !== undefined && { path: redact(t.path) }),
      ...(t.note !== undefined && { note: redact(t.note) }),
    })),
  };
}

export function buildExplainJsonError(message: string): ExplainJsonError {
  return { schemaVersion: 1, error: message };
}
