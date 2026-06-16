// Tests for checkGate — the approval-gate self-test. Mocks the policy evaluator
// so each branch (gate off / gate on) is exercised deterministically.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { evaluatePolicy } from '../../policy';
import { checkGate } from '../gate';
import type { CheckContext } from '../types';

vi.mock('../../policy', () => ({ evaluatePolicy: vi.fn() }));
const mockEval = vi.mocked(evaluatePolicy);

const ctx: CheckContext = { home: '/tmp', cwd: '/tmp' };

describe('checkGate', () => {
  beforeEach(() => mockEval.mockReset());

  it('reports the red, node9-fixable gap when the gate does NOT block rm -rf', async () => {
    mockEval.mockResolvedValue({ decision: 'allow' } as never);
    const findings = await checkGate(ctx);
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.category).toBe('Approval gate');
    expect(f.severity).toBe('critical');
    expect(f.owner).toBe('node9'); // node9-fixable, not "only you"
    expect(f.fix).toContain('shield enable bash-safe');
    expect(f.coverageProbe).toBeUndefined(); // a real gap, not a coverage probe
  });

  it('reports node9 as the approval gate (positive, coverage-probed) when rm -rf IS blocked', async () => {
    mockEval.mockResolvedValue({
      decision: 'block',
      ruleName: 'shield:bash-safe:block-rm-root',
    } as never);
    const findings = await checkGate(ctx);
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.title).toMatch(/approval gate/i);
    // Positive: advisory + a command coverage-probe so annotateCoverage marks it
    // 🟢 covered when enforcing, and redundantWhenOpen drops it if not wired.
    expect(f.severity).toBe('advisory');
    expect(f.coverageProbe).toEqual({ kind: 'command', command: 'rm -rf /' });
    expect(f.redundantWhenOpen).toBe(true);
    // No more obfuscation "slips through" detail / owner:'os' defeatism.
    expect(f.detail).toEqual([]);
    expect(f.owner).toBe('node9');
  });
});
