import { describe, it, expect } from 'vitest';
import { computeHeadline } from '../tui/dashboard/views/report/index.js';
import { EMPTY_FILTERED_SCAN } from '../tui/dashboard/views/report/derive.js';
import type { LoopFinding } from '../cli/commands/scan';

// The headline is the first sentence a user reads on the Report screen. It
// used to price loops itself and got three things wrong at once, landing on a
// plausible $9.73 while `node9 scan` said $48.66 from the same data.

const loop = (over: Partial<LoopFinding> = {}): LoopFinding => ({
  toolName: 'Edit',
  commandPreview: '/tmp/x.ts',
  count: 50,
  timestamp: '2026-09-01T00:00:00Z',
  project: 'p',
  sessionId: 's1',
  agent: 'claude',
  kind: 'loop',
  ...over,
});

const ready = { status: 'ready' } as Parameters<typeof computeHeadline>[0];

const scan = (loops: LoopFinding[]) => ({
  ...EMPTY_FILTERED_SCAN,
  loops,
});

describe('computeHeadline — loops', () => {
  it('reports counts and never a dollar figure', () => {
    const h = computeHeadline(ready, scan(Array.from({ length: 150 }, () => loop())), null);
    expect(h?.text).not.toMatch(/\$/);
  });

  it('separates sustained work from genuinely stuck patterns', () => {
    // 120 long-iteration + 30 real. The old line called all 150 "loops" and
    // billed every iteration of all of them.
    const loops = [
      ...Array.from({ length: 120 }, () => loop({ kind: 'long-iteration' })),
      ...Array.from({ length: 30 }, () => loop({ kind: 'loop' })),
    ];
    const h = computeHeadline(ready, scan(loops), null);
    expect(h?.text).toContain('150');
    expect(h?.text).toContain('30');
  });

  it('says zero stuck when every finding is sustained work', () => {
    const loops = Array.from({ length: 150 }, () => loop({ kind: 'long-iteration' }));
    const h = computeHeadline(ready, scan(loops), null);
    expect(h?.text).toMatch(/\b0\b/);
  });

  it('counts a finding with no kind as stuck, matching the rest of the codebase', () => {
    // `kind` is optional for legacy data; excluding those would under-report,
    // which is the direction this product keeps failing in.
    const legacy = loop();
    delete (legacy as { kind?: unknown }).kind;
    const h = computeHeadline(ready, scan(Array.from({ length: 150 }, () => legacy)), null);
    expect(h?.text).toContain('150');
  });

  it('leaves the >100 threshold alone', () => {
    const under = computeHeadline(ready, scan(Array.from({ length: 100 }, () => loop())), null);
    const over = computeHeadline(ready, scan(Array.from({ length: 101 }, () => loop())), null);
    expect(under?.text ?? '').not.toContain('repeated patterns');
    expect(over?.text).toContain('repeated patterns');
  });

  it('still yields to leaks, which outrank loops', () => {
    const h = computeHeadline(
      ready,
      {
        ...scan(Array.from({ length: 150 }, () => loop())),
        leaks: [{} as never],
      },
      null
    );
    expect(h?.text).toContain('leak');
  });
});
