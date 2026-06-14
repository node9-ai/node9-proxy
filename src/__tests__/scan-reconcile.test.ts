// src/__tests__/scan-reconcile.test.ts
//
// TIER 0 — scan-signal reconcile net (see doc/architecture-unified.md).
//
// The cloud Sessions tab's per-session scan signals come from whatever the
// proxy UPLOADS to /scan/report. TWO independent proxy paths feed that one
// `ScanSessionSignals` table:
//   • daemon tick        → buildSessionDeltas (daemon/sync.ts)        → sessionDeltas (BE increments)
//   • `scan --upload-history` → buildSessionTotals (scan-upload-history.ts) → sessionTotals (BE overwrites)
//
// Both turn the SAME `ScanFinding[]` into per-session `ScanSignals` — but each
// keeps its OWN private copy of the finding-type → signal-key map
// (`FINDING_TO_SIGNAL`) and the empty-signals seed (sync.ts:37/50 vs
// scan-upload-history.ts:50/63; the sync.ts copy even has a comment admitting
// it's a duplicate). They are identical TODAY, but they are two
// implementations: add a `ScanFinding` type and update only one map, and a
// user's cloud numbers would differ depending on whether their history reached
// the cloud via live ticks or a one-shot backfill — the same drift class as
// "Cost shows only Claude", one metric derived in two places.
//
// This is the tripwire: on one shared fixture that exercises EVERY finding type
// (plus repeats and a findingless-but-active session), the two aggregators must
// produce IDENTICAL per-session signals. Unlike cost (hardcoded table vs
// LiteLLM → a 2.5x band), scan signals are integer counts off a shared upstream
// extractor, so this asserts EXACT equality.

import { describe, it, expect } from 'vitest';
import { buildSessionDeltas } from '../daemon/sync.js';
import { buildSessionTotals } from '../scan-upload-history.js';
import type { ScanFinding } from '@node9/policy-engine';

const ALL_TYPES: ScanFinding['type'][] = [
  'dlp',
  'pii',
  'sensitive-file-read',
  'privilege-escalation',
  'network-exfil',
  'pipe-to-shell',
  'eval-of-remote',
  'destructive-op',
  'loop',
  'long-output-redacted',
];

const finding = (sessionId: string, type: ScanFinding['type'], lineIndex = 0): ScanFinding => ({
  sessionId,
  type,
  lineIndex,
});

// Both aggregators return [{ runId, totalToolCalls, signals }] in Map-insertion
// order. Sort by runId so equality is order-independent. Generic so each side
// keeps its own return type (SessionDelta[] / SessionTotal[]).
const sorted = <T extends { runId: string }>(rows: T[]): T[] =>
  [...rows].sort((a, b) => a.runId.localeCompare(b.runId));

describe('TIER 0 — scan-signal reconcile (deltas ≡ totals)', () => {
  // Exercises every finding type across multiple sessions, includes repeats
  // (count > 1, not just presence), and a session with tool calls but no
  // findings (the dashboard still attributes its tool calls).
  function fixture(): { findings: ScanFinding[]; toolCalls: Record<string, number> } {
    const findings: ScanFinding[] = [
      // sid-A: one of every type → the WHOLE FINDING_TO_SIGNAL map is hit.
      ...ALL_TYPES.map((t, i) => finding('sid-A', t, i)),
      // sid-A: repeats prove counts accumulate, not just presence.
      finding('sid-A', 'dlp', 98),
      finding('sid-A', 'loop', 99),
      // sid-B: a different mix.
      finding('sid-B', 'pii'),
      finding('sid-B', 'destructive-op'),
    ];
    const toolCalls = { 'sid-A': 47, 'sid-B': 12, 'sid-quiet': 30 };
    return { findings, toolCalls };
  }

  it('per-session signals are IDENTICAL between the daemon-tick and backfill paths', () => {
    const { findings, toolCalls } = fixture();
    const deltas = sorted(buildSessionDeltas(findings, toolCalls));
    const totals = sorted(buildSessionTotals(findings, toolCalls));

    // Exact equality — runId, totalToolCalls, and every signal key.
    expect(deltas).toEqual(totals);
  });

  it('every ScanFinding type maps to the same signal on BOTH paths (whole-map coverage)', () => {
    // One finding of each type in its own session, so a per-type divergence in
    // either FINDING_TO_SIGNAL copy surfaces as a per-session mismatch.
    const findings = ALL_TYPES.map((t) => finding(`sid-${t}`, t));
    const toolCalls = Object.fromEntries(ALL_TYPES.map((t) => [`sid-${t}`, 1]));

    const deltas = sorted(buildSessionDeltas(findings, toolCalls));
    const totals = sorted(buildSessionTotals(findings, toolCalls));

    expect(deltas).toEqual(totals);
    // Sanity: each path recorded exactly one signal per session — guards a
    // silent both-empty pass if a type stopped mapping on both sides at once.
    for (const row of deltas) {
      const hits = Object.values(row.signals).reduce((s, n) => s + n, 0);
      expect(hits).toBe(1);
    }
  });

  it('a divergent mapping WOULD fail the net (proves the tripwire bites)', () => {
    // Simulate the bug class: one path's FINDING_TO_SIGNAL copy drifts so 'dlp'
    // findings land in piiFindings instead of dlpFindings.
    const { findings, toolCalls } = fixture();
    const deltas = sorted(buildSessionDeltas(findings, toolCalls));
    const drifted = sorted(buildSessionTotals(findings, toolCalls)).map((row) => ({
      ...row,
      signals: {
        ...row.signals,
        piiFindings: row.signals.piiFindings + row.signals.dlpFindings,
        dlpFindings: 0,
      },
    }));

    // The fixture must actually contain dlp findings, else the mutation is a
    // no-op and the test proves nothing.
    expect(deltas.some((r) => r.signals.dlpFindings > 0)).toBe(true);
    // The exact-equality assertion the net relies on must reject the drift.
    expect(deltas).not.toEqual(drifted);
  });
});
