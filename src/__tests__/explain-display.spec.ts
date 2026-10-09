// Unit: the render-boundary helpers behind `node9 explain` output.
// Reported on node9-proxy discussion #168: a newline or terminal escape in the
// inspected command could print a forged `Decision:` line, and the Input line
// printed the command without redaction.

import { describe, it, expect } from 'vitest';
import {
  displaySafe,
  inputPreview,
  buildExplainJson,
  buildExplainJsonError,
  INPUT_PREVIEW_MAX,
} from '../cli/render/explain-display';
import type { ExplainResult } from '../policy';

// Built from parts at runtime so the source file holds no secret-shaped literal.
const SECRET_PART = 'pw-canary-5530';
const DB_URL = ['postgres', '://', 'app:', SECRET_PART, '@db.corp-internal.net/main'].join('');

describe('displaySafe', () => {
  it('keeps a forged Decision line on the same visible line', () => {
    const out = displaySafe('echo hi\n  Decision: ✅ ALLOW');
    expect(out).not.toContain('\n');
    expect(out).toBe('echo hi\\n  Decision: ✅ ALLOW');
  });

  it('makes CR, ESC and tab visible', () => {
    expect(displaySafe('a\rb')).toBe('a\\rb');
    expect(displaySafe('a\x1b[2Kb')).toBe('a\\x1b[2Kb');
    expect(displaySafe('a\tb')).toBe('a\\tb');
  });

  it('makes other C0, DEL, C1, line separators and bidi controls visible', () => {
    for (const c of [
      '\x00',
      '\x07',
      '\x7f',
      '\x85',
      '\x9b',
      '\u2028',
      '\u2029',
      '\u202e',
      '\u2066',
    ]) {
      const out = displaySafe(`a${c}b`);
      expect(out, JSON.stringify(c)).not.toContain(c);
      expect(out).toMatch(/^a\\u[0-9a-f]{4}b$/);
    }
  });

  it('leaves ordinary text, including non-ASCII letters and emoji, unchanged', () => {
    const s = 'ls -la ./café/日本 🚀';
    expect(displaySafe(s)).toBe(s);
  });

  it('redacts a DLP-shaped value', () => {
    const out = displaySafe(`psql ${DB_URL}`);
    expect(out).not.toContain(SECRET_PART);
    expect(out).toContain('[node9-redacted:');
  });
});

describe('inputPreview', () => {
  it('truncates after sanitizing, so a secret is never cut in half', () => {
    // Put the secret right at the truncation boundary.
    const raw = 'x'.repeat(INPUT_PREVIEW_MAX - 30) + ' ' + DB_URL;
    const out = inputPreview(raw);
    expect(out).not.toContain(SECRET_PART);
    expect(out).not.toContain(SECRET_PART.slice(0, 6));
    expect(out.length).toBeLessThanOrEqual(INPUT_PREVIEW_MAX);
  });

  it('leaves a short input whole', () => {
    expect(inputPreview('git status')).toBe('git status');
  });
});

describe('buildExplainJson', () => {
  const result: ExplainResult = {
    tool: 'bash',
    args: { command: `psql ${DB_URL}` },
    waterfall: [{ tier: 1, label: 'Env vars', status: 'env', note: 'not set' }],
    steps: [
      { name: 'Input parsing', outcome: 'checked', detail: `field "command": "psql ${DB_URL}"` },
      { name: 'Smart rules', outcome: 'block', detail: 'matched', isFinal: true },
    ],
    decision: 'block',
    blockedByLabel: 'Smart Rule: example',
  };

  it('carries the decision, reason and steps, redacted', () => {
    const doc = buildExplainJson(result, `psql ${DB_URL}`);
    const text = JSON.stringify(doc);
    expect(doc.schemaVersion).toBe(1);
    expect(doc.decision).toBe('block');
    expect(doc.reason).toBe('Smart Rule: example');
    expect(doc.steps.map((s) => s.final)).toEqual([false, true]);
    expect(text).not.toContain(SECRET_PART);
  });

  it('keeps a forged Decision line inside one JSON string', () => {
    const doc = buildExplainJson({ ...result, steps: [] }, 'echo hi\n  Decision: ALLOW');
    const parsed = JSON.parse(JSON.stringify(doc));
    expect(parsed.decision).toBe('block');
    expect(parsed.input).toBe('echo hi\n  Decision: ALLOW');
  });

  it('uses null for a missing input and reason', () => {
    const doc = buildExplainJson({ ...result, blockedByLabel: undefined }, undefined);
    expect(doc.input).toBeNull();
    expect(doc.reason).toBeNull();
  });

  it('an error document has no decision field', () => {
    const doc = buildExplainJsonError('Invalid JSON in [args]');
    expect(doc).toEqual({ schemaVersion: 1, error: 'Invalid JSON in [args]' });
    expect('decision' in doc).toBe(false);
  });
});
