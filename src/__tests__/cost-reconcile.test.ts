// src/__tests__/cost-reconcile.test.ts
//
// TIER 0 — local↔upload cost reconcile net (see
// doc/architecture-numbers-pipeline.md).
//
// The cloud Report's cost = SUM of what the proxy UPLOADS (collectEntries →
// /cost-sync → CostEntry). The local `node9 report`/`monitor` cost = the LOCAL
// readers (load*CostAsync in cli/aggregate/report-audit.ts). These are two
// independent implementations; when they drift, the cloud silently shows
// different numbers than the terminal — that's exactly how "Cost shows only
// Claude" shipped.
//
// This test is the tripwire: on ONE shared fixture (claude + codex + gemini
// journals), every agent that contributes cost LOCALLY must also contribute
// cost to the UPLOAD, and vice-versa (presence parity), and the magnitudes
// must stay in the same ballpark (magnitude parity). A whole agent dropping
// out of either side — the actual bug class — fails this immediately.
//
// NOT asserted (yet): exact-equal totals. The local readers use a hardcoded
// price table while the upload path uses pricingFor(LiteLLM); unifying them is
// Tier 1. Until then this net catches the structural drift (missing agent),
// which is the high-severity class, and tolerates pricing-table deltas via the
// magnitude band. See the divergence catalog at the bottom of the arch doc.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  loadClaudeCostAsync,
  loadCodexCostAsync,
  loadGeminiCostAsync,
} from '../cli/aggregate/report-audit';
import { claudeSource } from '../costSync';
import { codexSource } from '../cost-codex';
import { geminiSource } from '../cost-gemini';

const WINDOW_START = new Date('2026-06-01T00:00:00Z');
const WINDOW_END = new Date('2026-06-30T23:59:59Z');

function uploadTotal(rows: { costUSD: number }[]): number {
  return rows.reduce((s, r) => s + r.costUSD, 0);
}

// Same-ballpark: neither side may be < 40% of the other. Generous enough to
// absorb the hardcoded-table vs LiteLLM pricing delta, tight enough that a
// dropped agent (orders of magnitude) trips it.
function sameBallpark(a: number, b: number): boolean {
  if (a === 0 && b === 0) return true;
  const lo = Math.min(a, b);
  const hi = Math.max(a, b);
  return lo / hi >= 0.4;
}

describe('TIER 0 — local↔upload cost reconcile', () => {
  let TMP: string;
  const homeSpy = vi.spyOn(os, 'homedir');

  beforeEach(() => {
    TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-reconcile-'));
    homeSpy.mockReturnValue(TMP); // upload sources read homedir
  });
  afterEach(() => {
    homeSpy.mockReset();
    try {
      fs.rmSync(TMP, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  function seedClaude(): void {
    const dir = path.join(TMP, '.claude', 'projects', '-home-nadav-proj');
    fs.mkdirSync(dir, { recursive: true });
    const line = JSON.stringify({
      type: 'assistant',
      timestamp: '2026-06-10T10:00:00.000Z',
      cwd: '/home/nadav/proj',
      message: {
        model: 'claude-haiku-4-5',
        usage: {
          input_tokens: 4000,
          output_tokens: 600,
          cache_creation_input_tokens: 0,
          cache_read_input_tokens: 0,
        },
      },
    });
    fs.writeFileSync(path.join(dir, 'sess-claude.jsonl'), line + '\n');
  }

  function seedCodex(): void {
    const dir = path.join(TMP, '.codex', 'sessions', '2026', '06', '10');
    fs.mkdirSync(dir, { recursive: true });
    const lines = [
      '{"type":"session_meta","payload":{"timestamp":"2026-06-10T10:00:00Z","id":"cx","cwd":"/home/nadav/proj"}}',
      '{"type":"turn_context","payload":{"model":"gpt-5"}}',
      '{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":6000,"cached_input_tokens":0,"output_tokens":400}}}}',
    ];
    fs.writeFileSync(path.join(dir, 'rollout-cx.jsonl'), lines.join('\n') + '\n');
  }

  function seedGemini(): void {
    const dir = path.join(TMP, '.gemini', 'tmp', 'proj', 'chats');
    fs.mkdirSync(dir, { recursive: true });
    const lines = [
      '{"sessionId":"gx","startTime":"2026-06-10T10:00:00Z"}',
      '{"id":"t1","timestamp":"2026-06-10T10:01:00Z","type":"gemini","model":"gemini-2.5-pro","tokens":{"input":5000,"output":300,"cached":0}}',
    ];
    fs.writeFileSync(path.join(dir, 'session-gx.jsonl'), lines.join('\n') + '\n');
  }

  it('presence parity — every agent present locally is present in the upload (and vice versa)', async () => {
    seedClaude();
    seedCodex();
    seedGemini();

    const claudeLocal = (
      await loadClaudeCostAsync(WINDOW_START, WINDOW_END, path.join(TMP, '.claude', 'projects'))
    ).total;
    const codexLocal = (
      await loadCodexCostAsync(WINDOW_START, WINDOW_END, path.join(TMP, '.codex', 'sessions'))
    ).total;
    const geminiLocal = (
      await loadGeminiCostAsync(WINDOW_START, WINDOW_END, path.join(TMP, '.gemini', 'tmp'))
    ).total;

    const claudeUp = uploadTotal(claudeSource.collect());
    const codexUp = uploadTotal(codexSource.collect());
    const geminiUp = uploadTotal(geminiSource.collect());

    // The bug-class catch: an agent contributing locally but $0 to the upload
    // (Codex stale path, missing Gemini source) — or the reverse.
    expect(claudeLocal > 0).toBe(claudeUp > 0);
    expect(codexLocal > 0).toBe(codexUp > 0);
    expect(geminiLocal > 0).toBe(geminiUp > 0);

    // Sanity: the fixture actually exercised all three (guards a silent
    // both-zero pass if a format detail regresses).
    expect(claudeLocal).toBeGreaterThan(0);
    expect(codexLocal).toBeGreaterThan(0);
    expect(geminiLocal).toBeGreaterThan(0);
  });

  it('magnitude parity — per-agent totals stay in the same ballpark', async () => {
    seedClaude();
    seedCodex();
    seedGemini();

    const pairs: Array<[string, number, number]> = [
      [
        'claude',
        (await loadClaudeCostAsync(WINDOW_START, WINDOW_END, path.join(TMP, '.claude', 'projects')))
          .total,
        uploadTotal(claudeSource.collect()),
      ],
      [
        'codex',
        (await loadCodexCostAsync(WINDOW_START, WINDOW_END, path.join(TMP, '.codex', 'sessions')))
          .total,
        uploadTotal(codexSource.collect()),
      ],
      [
        'gemini',
        (await loadGeminiCostAsync(WINDOW_START, WINDOW_END, path.join(TMP, '.gemini', 'tmp')))
          .total,
        uploadTotal(geminiSource.collect()),
      ],
    ];
    for (const [agent, local, up] of pairs) {
      expect(
        sameBallpark(local, up),
        `${agent}: local $${local.toFixed(4)} vs upload $${up.toFixed(4)} diverged > 2.5x`
      ).toBe(true);
    }
  });

  it('a missing upload source would FAIL the net (proves the tripwire bites)', async () => {
    // Simulate the original bug: gemini data exists locally but the upload
    // sees nothing (e.g. wrong path / source not registered). Presence parity
    // must catch it.
    seedGemini();
    const geminiLocal = (
      await loadGeminiCostAsync(WINDOW_START, WINDOW_END, path.join(TMP, '.gemini', 'tmp'))
    ).total;
    // Point the upload-side reader at an EMPTY home to mimic a dropped source.
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-empty-'));
    homeSpy.mockReturnValue(empty);
    const geminiUpBroken = uploadTotal(geminiSource.collect());
    fs.rmSync(empty, { recursive: true, force: true });

    expect(geminiLocal).toBeGreaterThan(0);
    expect(geminiUpBroken).toBe(0);
    // This inequality is exactly what the presence-parity assertion forbids.
    expect(geminiLocal > 0).not.toBe(geminiUpBroken > 0);
  });
});
