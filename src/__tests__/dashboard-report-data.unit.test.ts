/**
 * Unit tests for the Report [2] data loaders in src/tui/dashboard/data.ts.
 *
 * Two loaders ship in phase 3b:
 *   - loadReportAudit(period)  — thin wrapper around the shared aggregator
 *   - startScanWalk(onUpdate)  — background walker for scan-derived panels
 *
 * The aggregator itself has its own coverage in
 * report-audit-aggregate.unit.test.ts; here we exercise the dashboard's
 * use of it (smoke) and the scan-cache state machine.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanResult } from '../cli/commands/scan';

// Stub the scan walkers — they walk ~/.claude/projects which is slow and
// machine-dependent. We only care about the state-machine plumbing.
const emptyScan: ScanResult = {
  filesScanned: 0,
  sessions: 0,
  totalToolCalls: 0,
  bashCalls: 0,
  findings: [],
  dlpFindings: [],
  loopFindings: [],
  totalCostUSD: 0,
  firstDate: null,
  lastDate: null,
  sessionsWithEarlySecrets: 0,
};

vi.mock('../cli/commands/scan', () => ({
  scanClaudeHistory: vi.fn(() => emptyScan),
  scanGeminiHistory: vi.fn(() => emptyScan),
  scanCodexHistory: vi.fn(() => emptyScan),
}));

import { loadReportAudit, startScanWalk } from '../tui/dashboard/data';
import type { ScanCache } from '../tui/dashboard/types';

describe('loadReportAudit', () => {
  it('returns an AggregateResult with data + hasAuditFile + responseDlpEntries', () => {
    const result = loadReportAudit('7d');
    expect(result).toHaveProperty('data');
    expect(result).toHaveProperty('hasAuditFile');
    expect(result).toHaveProperty('responseDlpEntries');
    expect(result.data).toHaveProperty('total');
    expect(result.data).toHaveProperty('toolMap');
    expect(result.responseDlpEntries).toBeInstanceOf(Array);
  });
});

describe('startScanWalk', () => {
  let updates: ScanCache[];
  let collect: (cache: ScanCache) => void;

  beforeEach(() => {
    updates = [];
    collect = (cache: ScanCache) => updates.push(cache);
  });

  function flushImmediate(): Promise<void> {
    return new Promise((resolve) => setImmediate(resolve));
  }

  it('emits loading synchronously, then ready after setImmediate', async () => {
    startScanWalk(collect);
    expect(updates).toHaveLength(1);
    expect(updates[0]).toEqual({ status: 'loading' });

    await flushImmediate();
    expect(updates).toHaveLength(2);
    expect(updates[1].status).toBe('ready');
    if (updates[1].status === 'ready') {
      expect(updates[1].results.claude).toBe(emptyScan);
      expect(updates[1].results.gemini).toBe(emptyScan);
      expect(updates[1].results.codex).toBe(emptyScan);
      expect(typeof updates[1].readyAt).toBe('number');
    }
  });

  it('suppresses the ready callback when cancel() is called before completion', async () => {
    const cancel = startScanWalk(collect);
    expect(updates).toHaveLength(1); // loading fired immediately
    cancel(); // cancel before setImmediate runs

    await flushImmediate();
    // After cancel, no further updates should arrive
    expect(updates).toHaveLength(1);
    expect(updates[0]).toEqual({ status: 'loading' });
  });

  it('emits error state when a walker throws', async () => {
    const scanModule = await import('../cli/commands/scan.js');
    const original = scanModule.scanClaudeHistory;
    vi.mocked(scanModule.scanClaudeHistory).mockImplementationOnce(() => {
      throw new Error('boom');
    });

    startScanWalk(collect);
    await flushImmediate();

    const last = updates[updates.length - 1];
    expect(last.status).toBe('error');
    if (last.status === 'error') {
      expect(last.error.message).toBe('boom');
    }

    vi.mocked(scanModule.scanClaudeHistory).mockImplementation(original);
  });
});
