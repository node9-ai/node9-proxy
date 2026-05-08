/**
 * Unit tests for the dashboard's pure data-layer helpers in
 * src/tui/dashboard/data.ts. The interactive React surface is
 * deliberately not covered here — those would belong in a separate
 * suite using ink-testing-library once the component layer stabilizes
 * past the spike phase.
 *
 * Targets:
 *   - aggregateAudit  : count math, session/MCP set-uniqueness, loop counter,
 *                       byTool / byShell / byBlock sorting + truncation
 *   - aggregateCost   : window-bounded sum, day-overlap edge case
 *   - auditEntryToActivityEvent : verdict mapping, preview redaction fallback,
 *                                 deterministic id synthesis
 */

import { describe, expect, it } from 'vitest';
import { aggregateAudit, aggregateCost, auditEntryToActivityEvent } from '../tui/dashboard/data';
import type { DailyEntry } from '../costSync';

// ── shared minimal-shape helpers ──────────────────────────────────────────────

function entry(overrides: Record<string, unknown> = {}): unknown {
  return {
    ts: '2026-05-08T08:00:00.000Z',
    tool: 'Bash',
    decision: 'allow',
    source: 'daemon',
    ...overrides,
  };
}

const T_BASE = Date.parse('2026-05-08T00:00:00.000Z');

// ── aggregateAudit ────────────────────────────────────────────────────────────

describe('aggregateAudit', () => {
  it('returns zeros for an empty list', () => {
    const a = aggregateAudit([] as never, T_BASE);
    expect(a.total).toBe(0);
    expect(a.allow).toBe(0);
    expect(a.block).toBe(0);
    expect(a.review).toBe(0);
    expect(a.loops).toBe(0);
    expect(a.byTool).toEqual([]);
    expect(a.byShell).toEqual([]);
    expect(a.byBlock).toEqual([]);
  });

  it('counts allow/block/review across decisions', () => {
    const entries = [
      entry({ decision: 'allow' }),
      entry({ decision: 'observe-allow' }), // also allow
      entry({ decision: 'block' }),
      entry({ decision: 'review' }),
    ];
    const a = aggregateAudit(entries as never, T_BASE);
    expect(a.allow).toBe(2);
    expect(a.block).toBe(1);
    expect(a.review).toBe(1);
    expect(a.total).toBe(4);
  });

  it('counts loops independently of allow/block', () => {
    const entries = [
      entry({ decision: 'block', checkedBy: 'loop-detected' }),
      entry({ decision: 'block', checkedBy: 'loop-detected' }),
      entry({ decision: 'block', checkedBy: 'block-force-push' }),
    ];
    const a = aggregateAudit(entries as never, T_BASE);
    expect(a.loops).toBe(2);
    expect(a.block).toBe(3);
  });

  it('skips post-hook and response-dlp entries (noise)', () => {
    const entries = [
      entry({ decision: 'allow', source: 'post-hook' }),
      entry({ decision: 'allow', source: 'response-dlp' }),
      entry({ decision: 'allow', source: 'daemon' }),
    ];
    expect(aggregateAudit(entries as never, T_BASE).total).toBe(1);
  });

  it('respects the time window', () => {
    const entries = [
      entry({ ts: new Date(T_BASE - 86_400_000 * 2).toISOString() }), // 2d ago
      entry({ ts: new Date(T_BASE).toISOString() }), // in window
    ];
    expect(aggregateAudit(entries as never, T_BASE - 86_400_000).total).toBe(1);
  });

  it('counts unique sessions and MCP servers (sets, not events)', () => {
    const entries = [
      entry({ sessionId: 'a', mcpServer: 'pg' }),
      entry({ sessionId: 'a', mcpServer: 'pg' }),
      entry({ sessionId: 'b', mcpServer: 'redis' }),
      entry({ sessionId: 'a' }), // no mcp here
    ];
    const a = aggregateAudit(entries as never, T_BASE);
    expect(a.sessions).toBe(2);
    expect(a.mcpServers).toBe(2);
    expect(a.mcpCalls).toBe(3); // events that carry mcpServer
  });

  it('byTool: tracks calls + blocked, sorted desc, truncated to 5', () => {
    const entries = [
      entry({ tool: 'Bash', decision: 'allow' }),
      entry({ tool: 'Bash', decision: 'allow' }),
      entry({ tool: 'Bash', decision: 'block' }),
      entry({ tool: 'Read', decision: 'allow' }),
      entry({ tool: 'Edit', decision: 'allow' }),
      entry({ tool: 'Write', decision: 'allow' }),
      entry({ tool: 'Glob', decision: 'allow' }),
      entry({ tool: 'TaskUpdate', decision: 'allow' }),
    ];
    const a = aggregateAudit(entries as never, T_BASE);
    expect(a.byTool.length).toBe(5);
    expect(a.byTool[0]).toEqual({ tool: 'Bash', calls: 3, blocked: 1 });
    // Tail tools not on the list
    expect(a.byTool.find((t) => t.tool === 'TaskUpdate')).toBeUndefined();
  });

  it('byShell: extracts first token of args.command for Bash entries', () => {
    const entries = [
      entry({ tool: 'Bash', args: { command: 'git status' } }),
      entry({ tool: 'Bash', args: { command: 'git push --force' }, decision: 'block' }),
      entry({ tool: 'Bash', args: { command: 'tail -f log' } }),
      entry({ tool: 'Read', args: { command: 'should-not-count' } }), // wrong tool
    ];
    const a = aggregateAudit(entries as never, T_BASE);
    expect(a.byShell.find((s) => s.cmd === 'git')).toEqual({ cmd: 'git', count: 2, blocked: 1 });
    expect(a.byShell.find((s) => s.cmd === 'tail')?.count).toBe(1);
    expect(a.byShell.find((s) => s.cmd === 'should-not-count')).toBeUndefined();
  });

  it('byBlock: counts checkedBy values for non-allow rows only', () => {
    const entries = [
      entry({ decision: 'block', checkedBy: 'block-force-push' }),
      entry({ decision: 'block', checkedBy: 'block-force-push' }),
      entry({ decision: 'block', checkedBy: 'dlp-block' }),
      entry({ decision: 'allow', checkedBy: 'allowlist' }), // skipped
    ];
    const a = aggregateAudit(entries as never, T_BASE);
    expect(a.byBlock).toEqual([
      { rule: 'block-force-push', count: 2 },
      { rule: 'dlp-block', count: 1 },
    ]);
  });
});

// ── aggregateCost ─────────────────────────────────────────────────────────────

describe('aggregateCost', () => {
  function dailyEntry(overrides: Partial<DailyEntry> = {}): DailyEntry {
    return {
      date: '2026-05-08',
      model: 'claude-opus-4-7',
      costUSD: 0.5,
      inputTokens: 1000,
      outputTokens: 500,
      cacheReadTokens: 200,
      cacheWriteTokens: 100,
      ...overrides,
    };
  }

  it('sums entries within window', () => {
    const entries = [
      dailyEntry({ date: '2026-05-08', costUSD: 1.0 }),
      dailyEntry({ date: '2026-05-08', costUSD: 0.5 }),
    ];
    const startMs = Date.parse('2026-05-08T00:00:00Z');
    const endMs = Date.parse('2026-05-08T23:59:59Z');
    const c = aggregateCost(entries, startMs, endMs);
    expect(c.totalUSD).toBeCloseTo(1.5);
    expect(c.loaded).toBe(true);
  });

  it('excludes entries outside window', () => {
    const entries = [
      dailyEntry({ date: '2026-05-01' }), // 7d ago
      dailyEntry({ date: '2026-05-08' }), // in window
    ];
    const startMs = Date.parse('2026-05-07T00:00:00Z');
    const endMs = Date.parse('2026-05-08T23:59:59Z');
    const c = aggregateCost(entries, startMs, endMs);
    expect(c.totalUSD).toBeCloseTo(0.5); // only second entry
  });

  it('includes a day if any portion overlaps the window (left edge)', () => {
    // Entry dated 2026-05-07. Window starts noon on 2026-05-07.
    // Day-of-entry overlaps — should be included.
    const entries = [dailyEntry({ date: '2026-05-07', costUSD: 2.0 })];
    const startMs = Date.parse('2026-05-07T12:00:00Z');
    const endMs = Date.parse('2026-05-08T00:00:00Z');
    const c = aggregateCost(entries, startMs, endMs);
    expect(c.totalUSD).toBe(2.0);
  });

  it('returns zeros for empty input but loaded=true', () => {
    const c = aggregateCost([], 0, Date.now());
    expect(c.totalUSD).toBe(0);
    expect(c.inputTokens).toBe(0);
    expect(c.loaded).toBe(true);
  });

  it('skips entries with unparseable dates (defensive)', () => {
    const entries = [
      dailyEntry({ date: 'not-a-date', costUSD: 99 }),
      dailyEntry({ date: '2026-05-08', costUSD: 1 }),
    ];
    const startMs = Date.parse('2026-05-08T00:00:00Z');
    const c = aggregateCost(entries, startMs, Date.now());
    expect(c.totalUSD).toBe(1);
  });
});

// ── auditEntryToActivityEvent ────────────────────────────────────────────────

describe('auditEntryToActivityEvent', () => {
  it('maps decision → verdict (allow / block / review)', () => {
    const allow = auditEntryToActivityEvent(
      { ts: '2026-05-08T08:00:00.000Z', tool: 'Read', decision: 'allow' } as never,
      0
    );
    if (allow.kind !== 'tool') throw new Error('expected tool kind');
    expect(allow.verdict).toBe('allow');

    const block = auditEntryToActivityEvent(
      { ts: '2026-05-08T08:00:00.000Z', tool: 'Bash', decision: 'block' } as never,
      0
    );
    if (block.kind !== 'tool') throw new Error('expected tool kind');
    expect(block.verdict).toBe('block');

    const review = auditEntryToActivityEvent(
      { ts: '2026-05-08T08:00:00.000Z', tool: 'Read', decision: 'review' } as never,
      0
    );
    if (review.kind !== 'tool') throw new Error('expected tool kind');
    expect(review.verdict).toBe('review');

    // observe-allow normalizes to allow
    const observe = auditEntryToActivityEvent(
      { ts: '2026-05-08T08:00:00.000Z', tool: 'Read', decision: 'observe-allow' } as never,
      0
    );
    if (observe.kind !== 'tool') throw new Error('expected tool kind');
    expect(observe.verdict).toBe('allow');
  });

  it('falls back to checkedBy rule when args is hashed (privacy default)', () => {
    // PreToolUse rows store argsHash, never plaintext, when
    // auditHashArgs=true. Surface the rule name instead of a generic
    // "(redacted)" — much more informative for the user.
    const e = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Bash',
        decision: 'block',
        args: { argsHash: 'abc123' },
        checkedBy: 'block-force-push',
      } as never,
      0
    );
    if (e.kind !== 'tool') throw new Error('expected tool kind');
    expect(e.preview).toBe('→ block-force-push');
  });

  it('falls back to (no preview) when args is hashed AND no checkedBy', () => {
    // Rare: audit row with no plaintext args and no rule attribution.
    // Surface a sentinel rather than the raw "{}" or "{argsHash:...}".
    const e = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Bash',
        decision: 'allow',
        args: { argsHash: 'abc123' },
      } as never,
      0
    );
    if (e.kind !== 'tool') throw new Error('expected tool kind');
    expect(e.preview).toBe('(no preview)');
  });

  it('uses args.command when present', () => {
    const e = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Bash',
        decision: 'allow',
        args: { command: 'git push --force' },
      } as never,
      0
    );
    if (e.kind !== 'tool') throw new Error('expected tool kind');
    expect(e.preview).toBe('git push --force');
  });

  it('truncates preview at 70 chars', () => {
    const long = 'x'.repeat(200);
    const e = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Bash',
        decision: 'allow',
        args: { command: long },
      } as never,
      0
    );
    if (e.kind !== 'tool') throw new Error('expected tool kind');
    expect(e.preview.length).toBe(70);
  });

  it('falls back to file_path or path when command is missing', () => {
    const fp = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Read',
        decision: 'allow',
        args: { file_path: '/etc/passwd' },
      } as never,
      0
    );
    if (fp.kind !== 'tool') throw new Error('expected tool kind');
    expect(fp.preview).toBe('/etc/passwd');

    const p = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Glob',
        decision: 'allow',
        args: { path: 'src/**' },
      } as never,
      0
    );
    if (p.kind !== 'tool') throw new Error('expected tool kind');
    expect(p.preview).toBe('src/**');
  });

  it('synthesizes deterministic ids prefixed with "audit-"', () => {
    const e1 = auditEntryToActivityEvent(
      { ts: '2026-05-08T08:00:00.000Z', tool: 'Bash', decision: 'allow' } as never,
      0
    );
    const e2 = auditEntryToActivityEvent(
      { ts: '2026-05-08T08:00:00.000Z', tool: 'Bash', decision: 'allow' } as never,
      1
    );
    expect(e1.id.startsWith('audit-')).toBe(true);
    // Same content + different index → different ids (no React-key collision)
    expect(e1.id).not.toBe(e2.id);
  });

  it('preserves agent / sessionId / mcpServer / checkedBy when present', () => {
    const e = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Bash',
        decision: 'block',
        agent: 'claude',
        sessionId: 'sess-abc',
        mcpServer: 'pg',
        checkedBy: 'block-force-push',
      } as never,
      0
    );
    if (e.kind !== 'tool') throw new Error('expected tool kind');
    expect(e.agent).toBe('claude');
    expect(e.sessionId).toBe('sess-abc');
    expect(e.mcpServer).toBe('pg');
    expect(e.checkedBy).toBe('block-force-push');
  });
});
