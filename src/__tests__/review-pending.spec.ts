/**
 * Unit tests for the inline-ask outcome-capture side store (phase 4).
 * Isolated via NODE9_PENDING_STORE → a temp file (never touches ~/.node9).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { reviewCorrelationKey, recordPendingReview, resolvePendingReview } from '../review-pending';

let store: string;
beforeEach(() => {
  store = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'node9-pending-')), 'pending.json');
  process.env.NODE9_PENDING_STORE = store;
});
afterEach(() => {
  delete process.env.NODE9_PENDING_STORE;
  try {
    fs.rmSync(path.dirname(store), { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('reviewCorrelationKey', () => {
  it('uses tool_use_id when present (Claude)', () => {
    expect(reviewCorrelationKey({ tool_use_id: 'toolu_1', tool_name: 'Bash' })).toBe(
      'tuid:toolu_1'
    );
  });

  it('falls back to session+tool+args-hash when no tool_use_id (Copilot)', () => {
    const k = reviewCorrelationKey({
      session_id: 's1',
      tool_name: 'Bash',
      tool_input: { command: 'git push' },
    });
    expect(k).toMatch(/^h:s1\|Bash\|[0-9a-f]{32}$/);
  });

  it('is identical across Pre/Post when session+tool+args match (Copilot)', () => {
    const pre = reviewCorrelationKey({
      session_id: 's1',
      tool_name: 'Bash',
      tool_input: { command: 'git push', description: 'push' },
    });
    const post = reviewCorrelationKey({
      session_id: 's1',
      tool_name: 'Bash',
      tool_input: { command: 'git push', description: 'push' },
    });
    expect(pre).toBe(post);
  });

  it('honors conversationId as the session alias (Antigravity-shape)', () => {
    expect(
      reviewCorrelationKey({ conversationId: 'c1', tool_name: 'Bash', tool_input: {} })
    ).toMatch(/^h:c1\|Bash\|/);
  });

  it('returns null when uncorrelatable', () => {
    expect(reviewCorrelationKey({ tool_name: 'Bash' })).toBeNull(); // no id, no session
    expect(reviewCorrelationKey({})).toBeNull();
  });
});

describe('record / resolve roundtrip', () => {
  it('resolves a recorded key once, then misses (removed)', () => {
    recordPendingReview({ key: 'tuid:a', tool: 'Bash', ts: Date.now() });
    expect(resolvePendingReview('tuid:a')?.key).toBe('tuid:a');
    expect(resolvePendingReview('tuid:a')).toBeNull(); // consumed
  });

  it('resolve miss returns null and does not throw', () => {
    expect(resolvePendingReview('tuid:nope')).toBeNull();
  });

  it('resolves the OLDEST entry first for a duplicate key (FIFO)', () => {
    recordPendingReview({ key: 'dup', tool: 'Bash', ts: 1000, label: 'first' });
    recordPendingReview({ key: 'dup', tool: 'Bash', ts: 2000, label: 'second' });
    expect(resolvePendingReview('dup', 2001)?.label).toBe('first');
    expect(resolvePendingReview('dup', 2001)?.label).toBe('second');
  });
});

describe('prune', () => {
  it('drops entries older than the TTL on resolve', () => {
    const now = Date.now();
    recordPendingReview({ key: 'old', tool: 'Bash', ts: now - 7 * 60 * 60 * 1000 }); // 7h > 6h TTL
    // A resolve for a different key should prune the stale 'old' entry.
    resolvePendingReview('something-else', now);
    expect(resolvePendingReview('old', now)).toBeNull();
  });
});
