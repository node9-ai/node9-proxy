// src/__tests__/cost-gemini.test.ts
// cost-multi-agent Phase 1 — Gemini cost source reads ~/.gemini/tmp.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseGeminiSession, geminiSource, geminiPriceFor } from '../cost-gemini';
import { _resetPricingCache } from '../pricing/litellm';

// Gemini writes each turn TWICE with identical id+tokens (partial + final).
const META =
  '{"sessionId":"sess-g1","projectHash":"h","startTime":"2026-06-10T10:00:00.000Z","kind":"main"}';
const TURN =
  '{"id":"turn-1","timestamp":"2026-06-10T10:01:00.000Z","type":"gemini","model":"gemini-2.5-pro","tokens":{"input":1000,"output":200,"cached":400}}';
const TURN_DUP = TURN; // exact double-write

describe('parseGeminiSession', () => {
  it('dedups the double-write and bills fresh+cached+output', () => {
    const rows = parseGeminiSession([META, TURN, TURN_DUP], 'node9');
    expect(rows).toHaveLength(1);
    const e = rows[0];
    // input 1000 includes cached 400 → fresh 600.
    expect(e.inputTokens).toBe(600);
    expect(e.cacheReadTokens).toBe(400);
    expect(e.outputTokens).toBe(200);
    expect(e.date).toBe('2026-06-10');
    expect(e.model).toMatch(/gemini-2\.5-pro/i);
    expect(e.workingDir).toBe('node9');
    expect(e.runId).toBe('sess-g1');
    expect(e.costUSD).toBeGreaterThan(0);
  });

  it('skips lines without tokens/model/timestamp', () => {
    const rows = parseGeminiSession(
      [META, '{"id":"u1","timestamp":"2026-06-10T10:00:30Z","type":"user","content":"hi"}'],
      'node9'
    );
    expect(rows).toHaveLength(0);
  });

  it('prices a preview model via the same-tier fallback (not $0)', () => {
    const rows = parseGeminiSession(
      [
        META,
        '{"id":"t2","timestamp":"2026-06-10T11:00:00Z","type":"gemini","model":"gemini-3-flash-preview","tokens":{"input":500,"output":50,"cached":0}}',
      ],
      'node9'
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].costUSD).toBeGreaterThan(0);
  });
});

describe('geminiSource.collect', () => {
  let TMP: string;
  const homeSpy = vi.spyOn(os, 'homedir');

  beforeEach(() => {
    TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-gem-'));
    homeSpy.mockReturnValue(TMP);
  });
  afterEach(() => {
    homeSpy.mockReset();
    try {
      fs.rmSync(TMP, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  function writeSession(project: string, name: string, lines: string[]) {
    const dir = path.join(TMP, '.gemini', 'tmp', project, 'chats');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, name), lines.join('\n') + '\n');
  }

  it('available() reflects ~/.gemini/tmp presence', () => {
    expect(geminiSource.available()).toBe(false);
    writeSession('node9', 'session-x.jsonl', [META, TURN]);
    expect(geminiSource.available()).toBe(true);
  });

  it('collects per project with the project basename as workingDir', () => {
    writeSession('node9', 'session-x.jsonl', [META, TURN, TURN_DUP]);
    const entries = geminiSource.collect();
    expect(entries).toHaveLength(1);
    expect(entries[0].workingDir).toBe('node9');
    expect(entries[0].inputTokens).toBe(600);
  });

  it('returns [] when no gemini tmp exists', () => {
    expect(geminiSource.collect()).toEqual([]);
  });
});

// Regression: Gemini price is single-sourced through geminiPriceFor (the same
// fn the local `node9 sessions`/`scan` readers now delegate to). The local
// readers previously carried a stale hardcoded table where gemini-2.5-flash
// read $0.15/$0.60 — ~4x under the real $0.30/$2.50 — so local and cloud Gemini
// cost diverged. These pin the resolved rate to the LiteLLM value (now in the
// bundled snapshot) so that drift can't silently return.
describe('geminiPriceFor — single Gemini price source (no stale local copy)', () => {
  beforeEach(() => {
    // Resolve against the deterministic bundled snapshot (no primed memCache).
    _resetPricingCache();
  });

  it('prices gemini-2.5-flash at the LiteLLM rate $0.30/$2.50, not the old $0.15/$0.60', () => {
    const p = geminiPriceFor('gemini-2.5-flash');
    expect(p).not.toBeNull();
    expect(p!.input).toBe(0.3e-6);
    expect(p!.output).toBe(2.5e-6);
    // The stale local values must be gone.
    expect(p!.input).not.toBe(0.15e-6);
    expect(p!.output).not.toBe(0.6e-6);
  });

  it('prices gemini-2.5-pro at $1.25/$10', () => {
    const p = geminiPriceFor('gemini-2.5-pro');
    expect(p).toEqual({ input: 1.25e-6, output: 10e-6, cacheRead: 0.125e-6 });
  });

  it('resolves preview/dated model ids to the same rate (no matching regression)', () => {
    expect(geminiPriceFor('gemini-2.5-flash-preview-05-20')).toEqual(
      geminiPriceFor('gemini-2.5-flash')
    );
  });

  it('falls back (not null) for a gemini model absent from the table, e.g. gemini-3-flash', () => {
    // LiteLLM has no gemini-3-flash; the fallback chain lands on gemini-2.5-flash
    // — the SAME fallback the upload path uses, so local and cloud still agree.
    const p = geminiPriceFor('gemini-3-flash');
    expect(p).toEqual(geminiPriceFor('gemini-2.5-flash'));
  });

  it('returns null for a genuinely unknown non-gemini model', () => {
    expect(geminiPriceFor('totally-not-a-model-xyz')).toBeNull();
  });
});
