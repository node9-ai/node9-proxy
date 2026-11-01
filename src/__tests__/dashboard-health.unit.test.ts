// Unit tests for the unified health-badge computation in the dashboard.
// computeHealthBadge is a pure function over the signal-source snapshots
// the dashboard already tracks; behavior is fully testable without React.
import { describe, expect, it } from 'vitest';
import { computeHealthBadge } from '../tui/dashboard/health';
import { EMPTY_SESSION_FORENSIC } from '../tui/dashboard/types';
import type {
  AuditAggregates,
  BlastSnapshot,
  ScanSignalsSnapshot,
  ShieldStatus,
} from '../tui/dashboard/types';

function emptyAgg(overrides: Partial<AuditAggregates> = {}): AuditAggregates {
  return {
    total: 0,
    allow: 0,
    block: 0,
    review: 0,
    loops: 0,
    dlpHits: 0,
    sessions: 0,
    mcpServers: 0,
    mcpCalls: 0,
    byTool: [],
    byBlock: [],
    byShell: [],
    ...overrides,
  };
}

function blast(overrides: Partial<BlastSnapshot> = {}): BlastSnapshot {
  return { paths: [], envFindings: 0, ...overrides };
}

function scan(overrides: Partial<ScanSignalsSnapshot> = {}): ScanSignalsSnapshot {
  return {
    loaded: true,
    pii: 0,
    sensitiveFileRead: 0,
    privilegeEscalation: 0,
    destructiveOp: 0,
    pipeToShell: 0,
    evalOfRemote: 0,
    longOutputRedacted: 0,
    ...overrides,
  };
}

function shields(overrides: Partial<ShieldStatus> = {}): ShieldStatus {
  return { active: [], inactive: [], ...overrides };
}

const baseInput = {
  agg: emptyAgg(),
  blast: blast(),
  scanSignals: scan(),
  shieldStatus: shields(),
  forensicAgg: { ...EMPTY_SESSION_FORENSIC },
  // Default: a healthy posture. The score cases override `posture` (fw#421:
  // the posture score is the one machine score; blast carries no score).
  posture: { score: 100, tier: 'good' as const },
};

describe('computeHealthBadge', () => {
  it('reports secure when all signals are clean', () => {
    const b = computeHealthBadge(baseInput);
    expect(b.severity).toBe('secure');
    expect(b.reasons).toEqual([]);
    expect(b.hint).toBeUndefined();
  });

  it('flips to critical on a single DLP hit', () => {
    const b = computeHealthBadge({ ...baseInput, agg: emptyAgg({ dlpHits: 1 }) });
    expect(b.severity).toBe('critical');
    expect(b.reasons).toContain('1 DLP');
    expect(b.hint).toBe('see node9 scan');
  });

  it('flips to critical on a single loop', () => {
    const b = computeHealthBadge({ ...baseInput, agg: emptyAgg({ loops: 1 }) });
    expect(b.severity).toBe('critical');
    expect(b.reasons).toContain('1 loops');
  });

  it('flips to critical on live privilege-escalation', () => {
    const b = computeHealthBadge({
      ...baseInput,
      forensicAgg: { ...EMPTY_SESSION_FORENSIC, privilegeEscalation: 1 },
    });
    expect(b.severity).toBe('critical');
    expect(b.reasons.some((r) => r.includes('severe forensic'))).toBe(true);
  });

  it('flips to critical on live destructive-op', () => {
    const b = computeHealthBadge({
      ...baseInput,
      forensicAgg: { ...EMPTY_SESSION_FORENSIC, destructiveOp: 1 },
    });
    expect(b.severity).toBe('critical');
  });

  it('flips to critical on live eval-of-remote', () => {
    const b = computeHealthBadge({
      ...baseInput,
      forensicAgg: { ...EMPTY_SESSION_FORENSIC, evalOfRemote: 1 },
    });
    expect(b.severity).toBe('critical');
  });

  it('flips to critical on historical privilege-escalation', () => {
    const b = computeHealthBadge({
      ...baseInput,
      scanSignals: scan({ privilegeEscalation: 3 }),
    });
    expect(b.severity).toBe('critical');
    expect(b.reasons.some((r) => r.includes('severe forensic'))).toBe(true);
  });

  it('flips to critical on a critical posture tier', () => {
    const b = computeHealthBadge({
      ...baseInput,
      posture: { score: 24, tier: 'critical' },
    });
    expect(b.severity).toBe('critical');
    expect(b.reasons).toContain('posture 24/100');
  });

  it('stays secure while the posture is still loading (null)', () => {
    expect(computeHealthBadge({ ...baseInput, posture: null }).severity).toBe('secure');
  });

  it('reports warning on an at-risk posture tier', () => {
    const b = computeHealthBadge({
      ...baseInput,
      posture: { score: 60, tier: 'at-risk' },
    });
    expect(b.severity).toBe('warning');
    expect(b.reasons).toContain('posture 60/100');
  });

  it('reports warning on PII alone', () => {
    const b = computeHealthBadge({
      ...baseInput,
      scanSignals: scan({ pii: 5 }),
    });
    expect(b.severity).toBe('warning');
    expect(b.reasons).toContain('5 forensic');
  });

  it('reports warning on reachable blast paths', () => {
    const b = computeHealthBadge({
      ...baseInput,
      blast: blast({
        paths: [
          { label: '/home/user/.ssh', description: '' },
          { label: '/home/user/.aws', description: '' },
        ],
      }),
    });
    expect(b.severity).toBe('warning');
    expect(b.reasons).toContain('2 paths');
  });

  it('reports warning on inactive shields', () => {
    const b = computeHealthBadge({
      ...baseInput,
      shieldStatus: shields({ inactive: ['block-force-push', 'dlp-saas-credit-card'] }),
    });
    expect(b.severity).toBe('warning');
    expect(b.reasons).toContain('2 shields off');
  });

  it('critical wins over warning when both apply', () => {
    const b = computeHealthBadge({
      ...baseInput,
      agg: emptyAgg({ dlpHits: 2 }),
      blast: blast({
        paths: [{ label: '/home/user/.ssh', description: '' }],
      }),
      shieldStatus: shields({ inactive: ['block-force-push'] }),
    });
    expect(b.severity).toBe('critical');
    // Reasons should include the critical signal; warning reasons don't
    // need to also be present (they are deferred when critical fires).
    expect(b.reasons).toContain('2 DLP');
  });

  it('caps reasons at 3 items even when many signals fire', () => {
    const b = computeHealthBadge({
      ...baseInput,
      agg: emptyAgg({ dlpHits: 1, loops: 1 }),
      posture: { score: 10, tier: 'critical' },
      forensicAgg: { ...EMPTY_SESSION_FORENSIC, privilegeEscalation: 1 },
    });
    expect(b.severity).toBe('critical');
    expect(b.reasons.length).toBeLessThanOrEqual(3);
  });

  it('tolerates null scanSignals (mount-time scan still in flight)', () => {
    const b = computeHealthBadge({ ...baseInput, scanSignals: null });
    expect(b.severity).toBe('secure');
  });

  it('tolerates null shieldStatus', () => {
    const b = computeHealthBadge({ ...baseInput, shieldStatus: null });
    expect(b.severity).toBe('secure');
  });

  it('omits hint on secure, includes hint on warning/critical', () => {
    expect(computeHealthBadge(baseInput).hint).toBeUndefined();
    expect(
      computeHealthBadge({ ...baseInput, posture: { score: 40, tier: 'critical' } }).hint
    ).toBe('see node9 posture');
    expect(computeHealthBadge({ ...baseInput, agg: emptyAgg({ dlpHits: 1 }) }).hint).toBe(
      'see node9 scan'
    );
  });

  it('aggregates live + historical forensic when both are nonzero', () => {
    const b = computeHealthBadge({
      ...baseInput,
      forensicAgg: { ...EMPTY_SESSION_FORENSIC, pii: 2 },
      scanSignals: scan({ pii: 5 }),
    });
    expect(b.severity).toBe('warning');
    expect(b.reasons).toContain('7 forensic');
  });
});
