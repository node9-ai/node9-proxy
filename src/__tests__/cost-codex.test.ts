// src/__tests__/cost-codex.test.ts
// cost-multi-agent Phase 1 — Codex cost source reads ~/.codex/sessions
// (repointed from the dead ~/.codex/log/codex-tui.log path).

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseCodexSession, codexSource, codexPriceFor } from '../cost-codex';
import { loadCodexCostAsync } from '../cli/aggregate/report-audit';
import { _resetPricingCache } from '../pricing/litellm';

// Real-shape codex session lines. total_token_usage is CUMULATIVE — the last
// token_count carries the session's final totals.
const SESSION = [
  '{"type":"session_meta","payload":{"timestamp":"2026-06-11T17:29:40.000Z","id":"sess-abc","cwd":"/home/nadav/node9"}}',
  '{"type":"turn_context","payload":{"model":"gpt-5.4","cwd":"/home/nadav/node9"}}',
  '{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1000,"cached_input_tokens":300,"output_tokens":50}}}}',
  '{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":2000,"cached_input_tokens":800,"output_tokens":120}}}}',
];

describe('parseCodexSession', () => {
  it('takes the final cumulative usage and attributes model/cwd/runId', () => {
    const e = parseCodexSession(SESSION)!;
    expect(e).not.toBeNull();
    // Last token_count wins (cumulative): input 2000, cached 800 → fresh 1200.
    expect(e.inputTokens).toBe(1200);
    expect(e.cacheReadTokens).toBe(800);
    expect(e.outputTokens).toBe(120);
    expect(e.cacheWriteTokens).toBe(0); // OpenAI: no cache-write
    expect(e.date).toBe('2026-06-11');
    expect(e.runId).toBe('sess-abc');
    expect(e.workingDir).toBe('/home/nadav/node9');
    expect(e.model).toMatch(/gpt-5/i);
    expect(e.costUSD).toBeGreaterThan(0);
  });

  it('returns null without a session_meta timestamp or any usage', () => {
    expect(parseCodexSession(['{"type":"turn_context","payload":{"model":"gpt-5.4"}}'])).toBeNull();
    expect(
      parseCodexSession([
        '{"type":"session_meta","payload":{"timestamp":"2026-06-11T00:00:00Z","id":"s"}}',
      ])
    ).toBeNull(); // meta but no token_count
  });

  it('still prices a session whose model field is absent (fallback, not $0)', () => {
    const e = parseCodexSession([
      '{"type":"session_meta","payload":{"timestamp":"2026-06-11T00:00:00Z","id":"s2"}}',
      '{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":500,"cached_input_tokens":0,"output_tokens":40}}}}',
    ])!;
    expect(e.inputTokens).toBe(500);
    expect(e.costUSD).toBeGreaterThan(0);
  });
});

describe('codexSource.collect', () => {
  let TMP: string;
  const homeSpy = vi.spyOn(os, 'homedir');

  beforeEach(() => {
    TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-codex-'));
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

  function writeSession(y: string, m: string, d: string, name: string, lines: string[]) {
    const dir = path.join(TMP, '.codex', 'sessions', y, m, d);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, name), lines.join('\n') + '\n');
  }

  it('available() reflects the sessions dir presence', () => {
    expect(codexSource.available()).toBe(false);
    writeSession('2026', '06', '11', 'rollout-a.jsonl', SESSION);
    expect(codexSource.available()).toBe(true);
  });

  it('emits one DailyEntry per session file', () => {
    writeSession('2026', '06', '11', 'rollout-a.jsonl', SESSION);
    const entries = codexSource.collect();
    expect(entries).toHaveLength(1);
    expect(entries[0].inputTokens).toBe(1200);
    expect(entries[0].runId).toBe('sess-abc');
  });

  it('returns [] when no sessions dir exists', () => {
    expect(codexSource.collect()).toEqual([]);
  });

  it('respects the sinceMs mtime cutoff', () => {
    writeSession('2026', '06', '11', 'rollout-old.jsonl', SESSION);
    const future = Date.now() + 60_000;
    expect(codexSource.collect(future)).toEqual([]);
  });
});

// Regression: Codex price is single-sourced through codexPriceFor (the same fn
// the local `node9 report` reader now delegates to, instead of a flat hardcoded
// gpt-5 rate). The local reader used to bill every session at $5/$15 regardless
// of model, while upload priced per-model via pricingFor — so local and cloud
// Codex cost diverged. These pin the resolved rate to the LiteLLM value and
// prove the local reader now prices per-model and fills byModel.
describe('codexPriceFor — single Codex price source (per-model, not flat gpt-5)', () => {
  beforeEach(() => _resetPricingCache());

  it('prices gpt-5-codex at the live LiteLLM rate $1.25/$10, not stale $10/$30 or flat $5/$15', () => {
    const [pin, pout, , pcr] = codexPriceFor('gpt-5-codex');
    expect(pin).toBe(1.25e-6);
    expect(pout).toBe(10e-6);
    expect(pcr).toBe(0.125e-6);
    expect(pin).not.toBe(5e-6); // old local flat input
    expect(pout).not.toBe(30e-6); // old stale bundled output
  });

  it('falls back (never $0) for a model absent from the table', () => {
    const t = codexPriceFor('gpt-9-codex-ultra');
    expect(t[0]).toBeGreaterThan(0);
    expect(t[1]).toBeGreaterThan(0);
  });
});

describe('local Codex reader — per-model breakdown, agrees with the upload price', () => {
  let TMP: string;
  beforeEach(() => {
    _resetPricingCache();
    TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-codex-bm-'));
  });
  afterEach(() => {
    try {
      fs.rmSync(TMP, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  it('prices per-model and fills byModel (gpt-5-codex at $1.25/$10, not the old flat rate)', async () => {
    const dir = path.join(TMP, '2026', '06', '10');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'rollout.jsonl'),
      [
        '{"type":"session_meta","payload":{"timestamp":"2026-06-10T10:00:00Z","id":"cx","cwd":"/p"}}',
        '{"type":"turn_context","payload":{"model":"gpt-5-codex"}}',
        '{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1000,"cached_input_tokens":0,"output_tokens":100}}}}',
      ].join('\n') + '\n'
    );
    const res = await loadCodexCostAsync(
      new Date('2026-06-01T00:00:00Z'),
      new Date('2026-06-30T23:59:59Z'),
      TMP
    );
    // 1000 input * $1.25/M + 100 output * $10/M = 0.00125 + 0.001 = 0.00225.
    // The old flat $5/$15 formula would have read 1000*5e-6 + 100*15e-6 = 0.0065.
    expect(res.total).toBeCloseTo(0.00225, 8);
    expect(res.total).not.toBeCloseTo(0.0065, 8);
    expect(res.byModel.get('gpt-5-codex')).toBeCloseTo(0.00225, 8);
  });
});
