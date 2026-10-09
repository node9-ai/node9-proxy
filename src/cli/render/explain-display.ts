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

/** Redact secrets, then make control and bidi characters visible. Redaction
 *  runs first, on the whole string, so a later truncation never cuts a secret
 *  in half and leaves part of it readable. */
export function displaySafe(text: string): string {
  return redactText(text).result.replace(UNSAFE_CHARS, toVisibleEscape);
}

export const INPUT_PREVIEW_MAX = 80;

/** The `Input:` line: sanitized first, truncated after. */
export function inputPreview(raw: string): string {
  const safe = displaySafe(raw);
  return safe.length > INPUT_PREVIEW_MAX ? safe.slice(0, INPUT_PREVIEW_MAX - 3) + '…' : safe;
}

/**
 * Wire schema for `node9 explain --json`. schemaVersion is locked at 1; a
 * breaking rename or removal must bump it. A document without `decision` is
 * a failure: errors are printed as { schemaVersion, error } with exit code 1.
 *
 * JSON.stringify already escapes control characters, so string fields here
 * are only redacted, not escaped.
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

const redact = (s: string): string => redactText(s).result;

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
    waterfall: result.waterfall,
  };
}

export function buildExplainJsonError(message: string): ExplainJsonError {
  return { schemaVersion: 1, error: message };
}
