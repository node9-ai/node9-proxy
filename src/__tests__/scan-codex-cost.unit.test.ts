// Unit test for scanCodexHistory cost — regression for the per-model pricing
// fix. The `node9 scan` Codex cost loop used to bill every session at a flat
// hardcoded $5/$15 (a "GPT-4o proxy"), diverging from `node9 report` and the
// upload path, which price per-model via codexPriceFor. Manual testing caught
// `scan` showing Codex $5.00 where `report` showed $1.25. This pins scan's
// Codex cost to the shared per-model source.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanCodexHistory } from '../cli/commands/scan';
import { _resetPricingCache } from '../pricing/litellm';

let tmpHome: string;

beforeEach(() => {
  _resetPricingCache(); // resolve against the deterministic bundled snapshot
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-codex-scan-'));
  vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

function writeCodexSession(model: string, inputTokens: number): void {
  const dir = path.join(tmpHome, '.codex', 'sessions', '2026', '06', '14');
  fs.mkdirSync(dir, { recursive: true });
  const lines = [
    '{"type":"session_meta","payload":{"timestamp":"2026-06-14T10:00:00Z","id":"cx","cwd":"/p"}}',
    `{"type":"turn_context","payload":{"model":"${model}"}}`,
    `{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":${inputTokens},"cached_input_tokens":0,"output_tokens":0}}}}`,
  ];
  fs.writeFileSync(path.join(dir, 'r.jsonl'), lines.join('\n') + '\n');
}

describe('scanCodexHistory cost — per-model via codexPriceFor (not flat gpt-5)', () => {
  it('prices a gpt-5-codex session at $1.25/M input, not the old flat $5/M', () => {
    writeCodexSession('gpt-5-codex', 1_000_000);
    const res = scanCodexHistory(null);
    // 1,000,000 input * $1.25/M = $1.25. The old flat formula read $5.00.
    expect(res.totalCostUSD).toBeCloseTo(1.25, 6);
    expect(res.totalCostUSD).not.toBeCloseTo(5.0, 6);
  });

  it('reads the session model rather than assuming gpt-5 — gpt-5-mini is cheaper', () => {
    // gpt-5-mini is $0.25/M input; a flat assumption would mis-bill it.
    writeCodexSession('gpt-5-mini', 1_000_000);
    const res = scanCodexHistory(null);
    expect(res.totalCostUSD).toBeCloseTo(0.25, 6);
  });
});

// Cross-surface tripwire (reconcile-net style): Codex price must be derived
// ONCE via codexPriceFor, never re-implemented as a flat hardcoded rate in a
// command. The bug was the flat `nonCached*5e-6 + cached*2.5e-6 + output*15e-6`
// formula copied into scan.ts AND sessions.ts (sessions' loop isn't exported,
// so this guards it). Catches a re-introduced hardcoded Codex rate in either.
describe('no command re-implements flat Codex pricing', () => {
  for (const rel of ['src/cli/commands/scan.ts', 'src/cli/commands/sessions.ts']) {
    it(`${rel} delegates to codexPriceFor (no flat output*15e-6 formula)`, () => {
      const src = fs.readFileSync(rel, 'utf8');
      expect(src).toContain('codexPriceFor');
      // The exact signature of the old flat Codex formula.
      expect(src).not.toMatch(/lastTotalOutput \* 15e-6/);
    });
  }
});
