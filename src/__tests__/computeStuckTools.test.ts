import { describe, it, expect } from 'vitest';
import { computeStuckTools, type StuckTool } from '../cli/commands/scan';
import type { LoopFinding } from '../cli/commands/scan';

function f(opts: { toolName: string; count: number }): LoopFinding {
  return {
    toolName: opts.toolName,
    commandPreview: 'test',
    count: opts.count,
    timestamp: '2026-04-29T00:00:00Z',
    project: 'p',
    sessionId: 's',
    agent: 'claude',
  };
}

describe('computeStuckTools', () => {
  it('returns empty when there are no loop findings', () => {
    expect(computeStuckTools([])).toEqual([]);
  });

  it('returns empty when total waste is below the noise threshold', () => {
    // Two tiny loops, total waste = 1+1 = 2, below 5
    const findings = [f({ toolName: 'Edit', count: 2 }), f({ toolName: 'Bash', count: 2 })];
    expect(computeStuckTools(findings)).toEqual([]);
  });

  it('aggregates waste per tool and computes percentage share', () => {
    // Edit: (5-1) + (4-1) = 7   Bash: (3-1) = 2   Total = 9
    const findings = [
      f({ toolName: 'Edit', count: 5 }),
      f({ toolName: 'Edit', count: 4 }),
      f({ toolName: 'Bash', count: 3 }),
    ];
    const result = computeStuckTools(findings);
    expect(result).toEqual<StuckTool[]>([
      { toolName: 'Edit', waste: 7, pct: 78 },
      { toolName: 'Bash', waste: 2, pct: 22 },
    ]);
  });

  it('sorts by waste descending', () => {
    const findings = [
      f({ toolName: 'A', count: 3 }), // waste 2
      f({ toolName: 'B', count: 6 }), // waste 5
      f({ toolName: 'C', count: 4 }), // waste 3
    ];
    const result = computeStuckTools(findings);
    expect(result.map((t) => t.toolName)).toEqual(['B', 'C', 'A']);
  });

  it('caps the result at the top 3 tools', () => {
    // 5 different tools, each wasting 4 calls (total 20)
    const findings = ['A', 'B', 'C', 'D', 'E'].map((name) => f({ toolName: name, count: 5 }));
    const result = computeStuckTools(findings);
    expect(result).toHaveLength(3);
  });

  it('skips findings whose count <= 1 (no waste)', () => {
    const findings = [
      f({ toolName: 'Edit', count: 1 }), // 0 waste — skipped
      f({ toolName: 'Edit', count: 8 }), // 7 waste
    ];
    const result = computeStuckTools(findings);
    expect(result).toEqual<StuckTool[]>([{ toolName: 'Edit', waste: 7, pct: 100 }]);
  });

  it('handles a single tool dominating waste at 100%', () => {
    const findings = [f({ toolName: 'Edit', count: 11 })]; // 10 waste
    const result = computeStuckTools(findings);
    expect(result).toEqual<StuckTool[]>([{ toolName: 'Edit', waste: 10, pct: 100 }]);
  });
});
