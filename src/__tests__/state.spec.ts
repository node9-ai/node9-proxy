// src/__tests__/state.spec.ts
// Unit tests for insightCounts persistence (loadInsightCounts / saveInsightCounts)
// and nudge-threshold boundary behaviour.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { insightCounts, loadInsightCounts, saveInsightCounts } from '../daemon/state.js';

// atomicWriteSync (inside saveInsightCounts) calls mkdirSync + writeFileSync + renameSync.
// Stub the FS side-effects at module level so no test ever hits disk.
vi.spyOn(fs, 'mkdirSync').mockReturnValue(undefined);
vi.spyOn(fs, 'renameSync').mockReturnValue(undefined);

beforeEach(() => {
  insightCounts.clear();
});

// Restore per-test spies (existsSync, readFileSync, writeFileSync) so their
// implementations don't leak between tests. The module-level mkdirSync/renameSync
// mocks are re-established by the vi.spyOn calls above on next module load.
afterEach(() => {
  vi.restoreAllMocks();
  // Re-stub the module-level mocks that restoreAllMocks just undid
  vi.spyOn(fs, 'mkdirSync').mockReturnValue(undefined);
  vi.spyOn(fs, 'renameSync').mockReturnValue(undefined);
});

// ── loadInsightCounts ─────────────────────────────────────────────────────────

describe('loadInsightCounts', () => {
  it('populates insightCounts from disk', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({ Read: 2, Write: 5 }));

    loadInsightCounts();

    expect(insightCounts.get('Read')).toBe(2);
    expect(insightCounts.get('Write')).toBe(5);
  });

  it('ignores entries with count <= 0', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({ Read: 0, Write: -1, Bash: 3 }));

    loadInsightCounts();

    expect(insightCounts.has('Read')).toBe(false);
    expect(insightCounts.has('Write')).toBe(false);
    expect(insightCounts.get('Bash')).toBe(3);
  });

  it('ignores entries with non-number values', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify({ Read: 'oops', Write: null, Bash: 2 })
    );

    loadInsightCounts();

    expect(insightCounts.has('Read')).toBe(false);
    expect(insightCounts.has('Write')).toBe(false);
    expect(insightCounts.get('Bash')).toBe(2);
  });

  it('is a no-op when the file does not exist', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);

    loadInsightCounts();

    expect(insightCounts.size).toBe(0);
  });

  it('does not throw when the file contains invalid JSON', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue('not-json');

    expect(() => loadInsightCounts()).not.toThrow();
    expect(insightCounts.size).toBe(0);
  });
});

// ── saveInsightCounts ─────────────────────────────────────────────────────────

describe('saveInsightCounts', () => {
  it('writes current insightCounts to disk', () => {
    insightCounts.set('Read', 2);
    insightCounts.set('Write', 5);
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    saveInsightCounts();

    expect(writeSpy).toHaveBeenCalledOnce();
    const written = JSON.parse(writeSpy.mock.calls[0][1] as string) as Record<string, number>;
    expect(written.Read).toBe(2);
    expect(written.Write).toBe(5);
  });

  it('writes an empty object when insightCounts is empty', () => {
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    saveInsightCounts();

    expect(writeSpy).toHaveBeenCalledOnce();
    const written = JSON.parse(writeSpy.mock.calls[0][1] as string);
    expect(written).toEqual({});
  });
});

// ── Nudge-threshold boundary ──────────────────────────────────────────────────
//
// The 💡 insight line is shown when allowCount >= 3 (ui.html / native.ts).
// allowCount sent to the UI = (insightCounts.get(tool) ?? 0) + 1.
// So the nudge fires when insightCounts reaches 2 (stored) → 3 (sent).
// These tests mirror the daemon's allow/deny mutation logic from server.ts.

describe('insightCounts nudge-threshold boundary', () => {
  function simulateAllow(tool: string) {
    insightCounts.set(tool, (insightCounts.get(tool) ?? 0) + 1);
  }
  function simulateDeny(tool: string) {
    insightCounts.delete(tool);
  }
  function allowCountSentToUI(tool: string): number {
    return (insightCounts.get(tool) ?? 0) + 1;
  }

  it('allowCount is 1 before any allows', () => {
    expect(allowCountSentToUI('Read')).toBe(1);
  });

  it('allowCount is 2 after one allow — nudge NOT shown (< 3)', () => {
    simulateAllow('Read');
    expect(allowCountSentToUI('Read')).toBe(2);
    expect(allowCountSentToUI('Read') >= 3).toBe(false);
  });

  it('allowCount is 3 after two allows — nudge IS shown (>= 3)', () => {
    simulateAllow('Read');
    simulateAllow('Read');
    expect(allowCountSentToUI('Read')).toBe(3);
    expect(allowCountSentToUI('Read') >= 3).toBe(true);
  });

  it('deny resets the counter — next allowCount is 1', () => {
    simulateAllow('Read');
    simulateAllow('Read');
    simulateDeny('Read');
    expect(allowCountSentToUI('Read')).toBe(1);
  });

  it('deny after zero allows is a no-op', () => {
    simulateDeny('Read');
    expect(allowCountSentToUI('Read')).toBe(1);
  });

  it('counters are independent per tool', () => {
    simulateAllow('Read');
    simulateAllow('Read');
    simulateAllow('Bash');

    expect(allowCountSentToUI('Read')).toBe(3);
    expect(allowCountSentToUI('Bash')).toBe(2);
  });

  it('nudge does not re-fire immediately after a deny', () => {
    simulateAllow('Write');
    simulateAllow('Write');
    simulateDeny('Write');
    simulateAllow('Write');
    expect(allowCountSentToUI('Write') >= 3).toBe(false);
  });

  it('nudge does not re-fire after Apply Rule resets the counter', () => {
    // server.ts calls insightCounts.delete(suggestion.toolName) on Apply Rule,
    // same operation as a deny. Verify the counter restarts from zero so the user
    // isn't immediately re-nudged after they've already acted on the suggestion.
    simulateAllow('Edit');
    simulateAllow('Edit');
    insightCounts.delete('Edit'); // mirrors server.ts Apply Rule handler
    simulateAllow('Edit');
    expect(allowCountSentToUI('Edit') >= 3).toBe(false); // still at 2, no nudge yet
  });
});
