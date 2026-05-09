/**
 * Unit tests for the dashboard's pure data-layer helpers in
 * src/tui/dashboard/data.ts. The interactive React surface is
 * deliberately not covered here — those would belong in a separate
 * suite using ink-testing-library once the component layer stabilizes
 * once the component layer is locked.
 *
 * Targets:
 *   - aggregateAudit  : count math, session/MCP set-uniqueness, loop counter,
 *                       byTool / byShell / byBlock sorting + truncation
 *   - aggregateCost   : window-bounded sum, day-overlap edge case
 *   - auditEntryToActivityEvent : verdict mapping, preview redaction fallback,
 *                                 deterministic id synthesis
 */

import { describe, expect, it } from 'vitest';
import {
  aggregateAudit,
  aggregateCost,
  applyForensicEvent,
  auditEntryToActivityEvent,
  buildCostBaseline,
  compactPath,
  isValidForensicEvent,
  mapResultStatus,
  subtractCostBaseline,
} from '../tui/dashboard/data';
import { EMPTY_SESSION_FORENSIC, type ForensicSseEvent } from '../tui/dashboard/types';
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

// ── compactPath ───────────────────────────────────────────────────────────────

describe('compactPath', () => {
  it('passes short paths (<= 3 segments) through unchanged', () => {
    expect(compactPath('/etc/passwd')).toBe('/etc/passwd');
    expect(compactPath('a/b/c')).toBe('a/b/c');
  });
  it('compacts long absolute paths to .../parent/file', () => {
    expect(compactPath('/home/nadav/node9/node9-proxy/src/tui/dashboard/data.ts')).toBe(
      '.../dashboard/data.ts'
    );
  });
  it('compacts long ~-relative paths', () => {
    expect(compactPath('~/projects/foo/bar/baz/main.ts')).toBe('.../baz/main.ts');
  });
  it('returns the input verbatim when not path-shaped', () => {
    expect(compactPath('git status')).toBe('git status');
    expect(compactPath('not_a_path')).toBe('not_a_path');
  });
  it('handles empty / undefined gracefully', () => {
    expect(compactPath('')).toBe('');
  });
});

// ── mapResultStatus ──────────────────────────────────────────────────────────

describe('mapResultStatus', () => {
  it('maps allow / observe-allow to "allow"', () => {
    expect(mapResultStatus('allow')).toBe('allow');
    expect(mapResultStatus('observe-allow')).toBe('allow');
  });
  it('maps every block-shaped status to "block"', () => {
    expect(mapResultStatus('block')).toBe('block');
    expect(mapResultStatus('dlp')).toBe('block');
    expect(mapResultStatus('denied')).toBe('block');
    expect(mapResultStatus('timeout')).toBe('block');
  });
  it('maps review to "review"', () => {
    expect(mapResultStatus('review')).toBe('review');
  });
  it('returns undefined for unknown / non-string', () => {
    expect(mapResultStatus('something-else')).toBeUndefined();
    expect(mapResultStatus(undefined)).toBeUndefined();
    expect(mapResultStatus(42)).toBeUndefined();
    expect(mapResultStatus(null)).toBeUndefined();
  });
});

// ── auditEntryToActivityEvent — extra coverage for path compaction in preview

describe('auditEntryToActivityEvent · preview compaction', () => {
  it('compacts long file_path in preview', () => {
    const e = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Edit',
        decision: 'allow',
        args: { file_path: '/home/u/repo/src/tui/dashboard/data.ts' },
      } as never,
      0
    );
    if (e.kind !== 'tool') throw new Error('expected tool');
    expect(e.preview).toBe('.../dashboard/data.ts');
  });

  it('does NOT compact a short command (Bash)', () => {
    const e = auditEntryToActivityEvent(
      {
        ts: '2026-05-08T08:00:00.000Z',
        tool: 'Bash',
        decision: 'allow',
        args: { command: 'git status' },
      } as never,
      0
    );
    if (e.kind !== 'tool') throw new Error('expected tool');
    expect(e.preview).toBe('git status');
  });
});

// ── aggregateCost.byModel ─────────────────────────────────────────────────────

describe('aggregateCost — byModel field', () => {
  function dailyEntry(overrides: Partial<DailyEntry> = {}): DailyEntry {
    return {
      date: '2026-05-08',
      model: 'claude-opus-4-7',
      costUSD: 1.0,
      inputTokens: 100,
      outputTokens: 50,
      cacheReadTokens: 200,
      cacheWriteTokens: 100,
      ...overrides,
    };
  }

  it('groups multi-day entries per model', () => {
    const startMs = Date.parse('2026-05-01T00:00:00Z');
    const c = aggregateCost(
      [
        dailyEntry({ date: '2026-05-07', model: 'claude-opus-4-7', costUSD: 5 }),
        dailyEntry({ date: '2026-05-08', model: 'claude-opus-4-7', costUSD: 3 }),
        dailyEntry({ date: '2026-05-08', model: 'claude-haiku-4-5', costUSD: 1 }),
      ],
      startMs
    );
    const opus = c.byModel.find((m) => m.model === 'claude-opus-4-7');
    expect(opus?.costUSD).toBeCloseTo(8);
  });

  it('sorts byModel desc by cost', () => {
    const startMs = Date.parse('2026-05-01T00:00:00Z');
    const c = aggregateCost(
      [
        dailyEntry({ model: 'claude-haiku-4-5', costUSD: 0.5 }),
        dailyEntry({ model: 'claude-opus-4-7', costUSD: 9 }),
        dailyEntry({ model: 'gpt-5', costUSD: 2 }),
      ],
      startMs
    );
    expect(c.byModel.map((m) => m.model)).toEqual(['claude-opus-4-7', 'gpt-5', 'claude-haiku-4-5']);
  });

  it('returns empty byModel array when no entries match window', () => {
    const c = aggregateCost(
      [dailyEntry({ date: '2026-04-01' })],
      Date.parse('2026-05-08T00:00:00Z')
    );
    expect(c.byModel).toEqual([]);
  });
});

// ── applyForensicEvent ────────────────────────────────────────────────────────

describe('applyForensicEvent', () => {
  function fEvent(
    category: ForensicSseEvent['category'],
    severity: 'critical' | 'warning' = 'warning'
  ): ForensicSseEvent {
    return {
      type: 'forensic',
      id: `fnd_${category}`,
      ts: 0,
      sessionId: 's1',
      category,
      severity,
    };
  }

  it('increments the matching counter for each forensic category', () => {
    let agg = { ...EMPTY_SESSION_FORENSIC };
    agg = applyForensicEvent(agg, fEvent('pii'));
    agg = applyForensicEvent(agg, fEvent('sensitive-file-read'));
    agg = applyForensicEvent(agg, fEvent('privilege-escalation', 'critical'));
    agg = applyForensicEvent(agg, fEvent('destructive-op', 'critical'));
    agg = applyForensicEvent(agg, fEvent('pipe-to-shell'));
    agg = applyForensicEvent(agg, fEvent('eval-of-remote', 'critical'));
    agg = applyForensicEvent(agg, fEvent('long-output-redacted'));
    expect(agg.pii).toBe(1);
    expect(agg.sensitiveFileRead).toBe(1);
    expect(agg.privilegeEscalation).toBe(1);
    expect(agg.destructiveOp).toBe(1);
    expect(agg.pipeToShell).toBe(1);
    expect(agg.evalOfRemote).toBe(1);
    expect(agg.longOutputRedacted).toBe(1);
  });

  it('skips dlp / loop / network-exfil — those are counted via audit aggregation', () => {
    let agg = { ...EMPTY_SESSION_FORENSIC };
    agg = applyForensicEvent(agg, fEvent('dlp'));
    agg = applyForensicEvent(agg, fEvent('loop'));
    agg = applyForensicEvent(agg, fEvent('network-exfil'));
    expect(agg).toEqual(EMPTY_SESSION_FORENSIC);
  });

  it('treats applyForensicEvent as a pure function (no input mutation)', () => {
    const before = { ...EMPTY_SESSION_FORENSIC };
    const snapshot = JSON.stringify(before);
    applyForensicEvent(before, fEvent('pii'));
    expect(JSON.stringify(before)).toBe(snapshot);
  });

  it('accumulates counts on the same category', () => {
    let agg = { ...EMPTY_SESSION_FORENSIC };
    agg = applyForensicEvent(agg, fEvent('pii'));
    agg = applyForensicEvent(agg, fEvent('pii'));
    agg = applyForensicEvent(agg, fEvent('pii'));
    expect(agg.pii).toBe(3);
  });
});

describe('isValidForensicEvent', () => {
  it('accepts a well-formed event', () => {
    expect(
      isValidForensicEvent({
        type: 'forensic',
        id: 'fnd_1',
        ts: 0,
        sessionId: 's1',
        category: 'pii',
        severity: 'warning',
      })
    ).toBe(true);
  });

  it('accepts every known category', () => {
    const categories: ForensicSseEvent['category'][] = [
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
    for (const c of categories) {
      expect(
        isValidForensicEvent({
          type: 'forensic',
          id: 'x',
          ts: 0,
          sessionId: 's',
          category: c,
          severity: 'warning',
        }),
        `category=${c}`
      ).toBe(true);
    }
  });

  it('rejects unknown categories (defends against daemon-side bugs)', () => {
    expect(
      isValidForensicEvent({
        type: 'forensic',
        id: 'x',
        ts: 0,
        sessionId: 's',
        category: 'made-up-category',
        severity: 'warning',
      })
    ).toBe(false);
  });

  it('rejects missing required fields', () => {
    expect(isValidForensicEvent({ id: 'x', category: 'pii' })).toBe(false);
    expect(isValidForensicEvent({ id: 'x', sessionId: 's', category: 'pii' })).toBe(true);
    expect(isValidForensicEvent({ sessionId: 's', category: 'pii' })).toBe(false);
  });

  it('rejects non-object inputs', () => {
    expect(isValidForensicEvent(null)).toBe(false);
    expect(isValidForensicEvent(undefined)).toBe(false);
    expect(isValidForensicEvent('string')).toBe(false);
    expect(isValidForensicEvent(42)).toBe(false);
    expect(isValidForensicEvent([])).toBe(false);
  });
});

describe('subtractCostBaseline', () => {
  function entry(overrides: Partial<DailyEntry> = {}): DailyEntry {
    return {
      date: '2026-05-09',
      model: 'claude-sonnet-4-6',
      costUSD: 0,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      ...overrides,
    };
  }

  it('returns identity when baseline is empty', () => {
    const entries = [entry({ costUSD: 5 })];
    const out = subtractCostBaseline(entries, new Map());
    expect(out).toEqual(entries);
  });

  it('zeroes out an entry that exactly matches the baseline (since-open delta = 0)', () => {
    const e = entry({ costUSD: 5, inputTokens: 100, outputTokens: 50 });
    const baseline = buildCostBaseline([e]);
    const out = subtractCostBaseline([e], baseline);
    expect(out[0].costUSD).toBe(0);
    expect(out[0].inputTokens).toBe(0);
    expect(out[0].outputTokens).toBe(0);
  });

  it('returns the delta when the entry has grown since baseline', () => {
    const baselineEntry = entry({ costUSD: 5, inputTokens: 100, outputTokens: 50 });
    const baseline = buildCostBaseline([baselineEntry]);
    const grown = entry({ costUSD: 12, inputTokens: 250, outputTokens: 80 });
    const out = subtractCostBaseline([grown], baseline);
    expect(out[0].costUSD).toBe(7);
    expect(out[0].inputTokens).toBe(150);
    expect(out[0].outputTokens).toBe(30);
  });

  it('passes through entries not present in the baseline (e.g. tomorrow or new model)', () => {
    const todayBaseline = entry({ date: '2026-05-09', costUSD: 5 });
    const baseline = buildCostBaseline([todayBaseline]);
    const tomorrow = entry({ date: '2026-05-10', costUSD: 3 });
    const newModel = entry({ model: 'claude-haiku-4-5', costUSD: 1 });
    const out = subtractCostBaseline([tomorrow, newModel], baseline);
    expect(out[0]).toEqual(tomorrow);
    expect(out[1]).toEqual(newModel);
  });

  it('clamps negative deltas to 0 (defensive against external data trims)', () => {
    const baseline = buildCostBaseline([entry({ costUSD: 10, inputTokens: 200 })]);
    const shrunk = entry({ costUSD: 4, inputTokens: 50 });
    const out = subtractCostBaseline([shrunk], baseline);
    expect(out[0].costUSD).toBe(0);
    expect(out[0].inputTokens).toBe(0);
  });

  it('preserves date and model on every output entry', () => {
    const baseline = buildCostBaseline([entry({ costUSD: 5 })]);
    const grown = entry({ costUSD: 12 });
    const out = subtractCostBaseline([grown], baseline);
    expect(out[0].date).toBe(grown.date);
    expect(out[0].model).toBe(grown.model);
  });

  it('does not mutate the input array', () => {
    const grown = entry({ costUSD: 12 });
    const before = JSON.stringify(grown);
    const baseline = buildCostBaseline([entry({ costUSD: 5 })]);
    subtractCostBaseline([grown], baseline);
    expect(JSON.stringify(grown)).toBe(before);
  });
});

describe('buildCostBaseline', () => {
  function entry(overrides: Partial<DailyEntry> = {}): DailyEntry {
    return {
      date: '2026-05-09',
      model: 'claude-sonnet-4-6',
      costUSD: 0,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      ...overrides,
    };
  }

  it('keys entries by `${date}|${model}`', () => {
    const a = entry({ date: '2026-05-09', model: 'claude-sonnet-4-6' });
    const b = entry({ date: '2026-05-09', model: 'claude-haiku-4-5' });
    const map = buildCostBaseline([a, b]);
    expect(map.size).toBe(2);
    expect(map.has('2026-05-09|claude-sonnet-4-6')).toBe(true);
    expect(map.has('2026-05-09|claude-haiku-4-5')).toBe(true);
  });

  it('clones each entry so caller mutations do not bleed into the baseline', () => {
    const a = entry({ costUSD: 5 });
    const map = buildCostBaseline([a]);
    a.costUSD = 999;
    expect(map.get('2026-05-09|claude-sonnet-4-6')!.costUSD).toBe(5);
  });

  it('returns an empty map for empty input', () => {
    expect(buildCostBaseline([]).size).toBe(0);
  });
});
