// Unit tests for resolveSessionId — the prefix/ambiguity logic behind
// `node9 session-taint clear <id>`. Pure, so no daemon is needed.

import { describe, it, expect } from 'vitest';
import { resolveSessionId } from '../cli/commands/session-taint';
import type { SessionTaintRecord } from '../daemon/taint-store';

const rec = (sessionId: string): SessionTaintRecord => ({
  sessionId,
  source: 'output-secret:X',
  createdAt: 0,
  expiresAt: Date.now() + 60_000,
});

describe('resolveSessionId', () => {
  it('resolves an exact id', () => {
    const r = resolveSessionId([rec('abc12345'), rec('def67890')], 'abc12345');
    expect('record' in r && r.record.sessionId).toBe('abc12345');
  });

  it('resolves a unique 8-char prefix', () => {
    const r = resolveSessionId([rec('abc12345-full-uuid'), rec('zzz99999')], 'abc12345');
    expect('record' in r && r.record.sessionId).toBe('abc12345-full-uuid');
  });

  it('reports not-found when nothing matches', () => {
    const r = resolveSessionId([rec('abc12345')], 'nope');
    expect(r).toEqual({ error: 'not-found' });
  });

  it('reports ambiguous when a prefix matches more than one', () => {
    const r = resolveSessionId([rec('abc111'), rec('abc222')], 'abc');
    expect('error' in r && r.error).toBe('ambiguous');
    expect('matches' in r && r.matches).toEqual(['abc111', 'abc222']);
  });

  it('prefers an exact match even when it is also a prefix of others', () => {
    const r = resolveSessionId([rec('abc'), rec('abcdef')], 'abc');
    expect('record' in r && r.record.sessionId).toBe('abc');
  });
});
