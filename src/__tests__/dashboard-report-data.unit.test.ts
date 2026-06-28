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
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
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
  scanClaudeHistoryAsync: vi.fn(async () => emptyScan),
  scanGeminiHistory: vi.fn(() => emptyScan),
  scanCodexHistory: vi.fn(() => emptyScan),
}));

import { loadReportAudit, startScanWalk } from '../tui/dashboard/data';
import type { ScanCache } from '../tui/dashboard/types';

// loadReportAudit reads ~/.node9/audit.log; isolate HOME so the test is fast and
// deterministic regardless of this machine's real (possibly huge) audit log.
const realHome = process.env.HOME;
const realProfile = process.env.USERPROFILE;
let tmpHome: string;
beforeAll(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-dash-'));
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
});
afterAll(() => {
  if (realHome === undefined) delete process.env.HOME;
  else process.env.HOME = realHome;
  if (realProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = realProfile;
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

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

  /** Drain setImmediate ticks until `predicate` becomes true or the cap is
   *  hit. The walker now yields between agents (claude → gemini → codex) so
   *  a single flush is no longer enough to reach 'ready'. */
  async function drainUntil(predicate: () => boolean, maxTicks = 20): Promise<void> {
    for (let i = 0; i < maxTicks; i++) {
      if (predicate()) return;
      await flushImmediate();
    }
  }

  it('emits loading synchronously, then ready after the walker yields complete', async () => {
    startScanWalk(collect);
    expect(updates).toHaveLength(1);
    expect(updates[0]).toEqual({ status: 'loading' });

    await drainUntil(() => updates.length >= 2);
    expect(updates).toHaveLength(2);
    expect(updates[1].status).toBe('ready');
    if (updates[1].status === 'ready') {
      expect(updates[1].results.claude).toBe(emptyScan);
      expect(updates[1].results.gemini).toBe(emptyScan);
      expect(updates[1].results.codex).toBe(emptyScan);
      expect(typeof updates[1].readyAt).toBe('number');
    }
  });

  it('yields to the event loop between agent walkers (UI stays responsive mid-walk)', async () => {
    // The walker calls scanClaudeHistory → yield → scanGeminiHistory →
    // yield → scanCodexHistory → emit ready. We pin the yielding by
    // counting how many times an independent setImmediate-driven ticker
    // fires before 'ready' arrives. Without yields between walkers the
    // tickers wouldn't run until ready was already emitted.
    let independentTicks = 0;
    const tick = (): void => {
      independentTicks++;
      if (independentTicks < 50) setImmediate(tick);
    };
    setImmediate(tick);

    startScanWalk(collect);
    await drainUntil(() => updates.some((u) => u.status === 'ready'));

    // 1 initial yield + 2 between-walker yields + 1 between-tick scheduling
    // = the independent ticker should fire at least 3 times before ready.
    expect(independentTicks).toBeGreaterThanOrEqual(3);
  });

  it('suppresses the ready callback when cancel() is called before completion', async () => {
    const cancel = startScanWalk(collect);
    expect(updates).toHaveLength(1); // loading fired immediately
    cancel(); // cancel before any walker runs

    await drainUntil(() => false, 5); // give yields a chance to fire
    // After cancel, no further updates should arrive
    expect(updates).toHaveLength(1);
    expect(updates[0]).toEqual({ status: 'loading' });
  });

  it('emits error state when a walker throws', async () => {
    const scanModule = await import('../cli/commands/scan.js');
    const original = scanModule.scanClaudeHistoryAsync;
    vi.mocked(scanModule.scanClaudeHistoryAsync).mockImplementationOnce(async () => {
      throw new Error('boom');
    });

    startScanWalk(collect);
    await drainUntil(() => updates.some((u) => u.status === 'error'));

    const last = updates[updates.length - 1];
    expect(last.status).toBe('error');
    if (last.status === 'error') {
      expect(last.error.message).toBe('boom');
    }

    vi.mocked(scanModule.scanClaudeHistoryAsync).mockImplementation(original);
  });
});
