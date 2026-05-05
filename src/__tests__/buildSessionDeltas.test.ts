import { describe, it, expect } from 'vitest';
import { buildSessionDeltas } from '../daemon/sync.js';
import type { ScanFinding } from '@node9/policy-engine';

const finding = (sessionId: string, type: ScanFinding['type'], lineIndex = 0): ScanFinding => ({
  sessionId,
  type,
  lineIndex,
});

describe('buildSessionDeltas', () => {
  it('groups findings by sessionId into per-session signal counts', () => {
    const deltas = buildSessionDeltas(
      [
        finding('sid-A', 'dlp'),
        finding('sid-A', 'dlp'),
        finding('sid-A', 'pii'),
        finding('sid-B', 'destructive-op'),
      ],
      { 'sid-A': 47, 'sid-B': 12 }
    );
    const a = deltas.find((d) => d.runId === 'sid-A')!;
    const b = deltas.find((d) => d.runId === 'sid-B')!;
    expect(a.signals.dlpFindings).toBe(2);
    expect(a.signals.piiFindings).toBe(1);
    expect(a.signals.destructiveOps).toBe(0);
    expect(a.totalToolCalls).toBe(47);
    expect(b.signals.destructiveOps).toBe(1);
    expect(b.totalToolCalls).toBe(12);
  });

  it('maps every finding type to the correct signal key', () => {
    // Pin the engine's finding-type → ScanSignals-key contract. If the
    // engine adds a new type, this test fails until we add the row.
    const types: ScanFinding['type'][] = [
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
    const deltas = buildSessionDeltas(
      types.map((t) => finding('sid-X', t)),
      { 'sid-X': types.length }
    );
    const s = deltas[0].signals;
    expect(s.dlpFindings).toBe(1);
    expect(s.piiFindings).toBe(1);
    expect(s.sensitiveFileReads).toBe(1);
    expect(s.privilegeEscalation).toBe(1);
    expect(s.networkExfil).toBe(1);
    expect(s.pipeToShell).toBe(1);
    expect(s.evalOfRemote).toBe(1);
    expect(s.destructiveOps).toBe(1);
    expect(s.loops).toBe(1);
    expect(s.longOutputRedactions).toBe(1);
  });

  it('includes sessions that had tool calls but zero findings', () => {
    // A session that ran 30 calls with nothing flagged still deserves a
    // row — the dashboard wants to attribute that count to the session.
    const deltas = buildSessionDeltas([], { 'sid-quiet': 30 });
    expect(deltas).toHaveLength(1);
    expect(deltas[0].runId).toBe('sid-quiet');
    expect(deltas[0].totalToolCalls).toBe(30);
    expect(deltas[0].signals.dlpFindings).toBe(0);
  });

  it('returns an empty array when no findings and no tool calls', () => {
    expect(buildSessionDeltas([], {})).toEqual([]);
  });

  it('produces independent signal objects per session (no shared reference)', () => {
    // Defensive: a shared emptySignals() object across sessions would let
    // findings on session A bleed into session B. Mutate one and check
    // the other doesn't see it.
    const deltas = buildSessionDeltas([], { 'sid-A': 1, 'sid-B': 1 });
    deltas[0].signals.dlpFindings = 999;
    expect(deltas[1].signals.dlpFindings).toBe(0);
  });

  it('does not double-count a session that has both findings and a toolCalls entry', () => {
    // Both pathways insert into the same Map — the toolCalls top-up loop
    // must check existence first, not blindly overwrite.
    const deltas = buildSessionDeltas([finding('sid-A', 'loop'), finding('sid-A', 'loop')], {
      'sid-A': 5,
    });
    expect(deltas).toHaveLength(1);
    expect(deltas[0].signals.loops).toBe(2);
    expect(deltas[0].totalToolCalls).toBe(5);
  });
});
