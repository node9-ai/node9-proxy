import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { listSessionFiles, sessionIdOf, usageKey } from '../session-files';

// The flat walk these replace missed 13.8% of real spend: sub-agent and
// workflow transcripts live one and two levels down, and nothing looked there.

let root: string;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-sessfiles-'));
  const proj = path.join(root, 'proj');
  fs.mkdirSync(path.join(proj, 'sess-1', 'subagents'), { recursive: true });
  fs.mkdirSync(path.join(proj, 'sess-1', 'wf_abc'), { recursive: true });
  fs.writeFileSync(path.join(proj, 'sess-1.jsonl'), '');
  fs.writeFileSync(path.join(proj, 'sess-1', 'subagents', 'agent-x.jsonl'), '');
  fs.writeFileSync(path.join(proj, 'sess-1', 'wf_abc', 'step-1.jsonl'), '');
  fs.writeFileSync(path.join(proj, 'notes.md'), '');
});

afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

describe('listSessionFiles', () => {
  const found = (): string[] => listSessionFiles(path.join(root, 'proj')).sort();

  it('finds nested transcripts a flat readdir never saw', () => {
    expect(found()).toEqual(
      [
        'sess-1.jsonl',
        path.join('sess-1', 'subagents', 'agent-x.jsonl'),
        path.join('sess-1', 'wf_abc', 'step-1.jsonl'),
      ].sort()
    );
  });

  it('does NOT skip agent-* files', () => {
    // Three callers carried `!f.startsWith('agent-')`, written for a layout
    // where agent transcripts sat at depth 1. Measured today: zero there, 458
    // nested. Keeping that filter would exclude exactly what we came for.
    expect(found().some((f) => f.includes('agent-x.jsonl'))).toBe(true);
  });

  it('returns paths relative to the project dir, so callers can still join', () => {
    for (const f of found()) expect(path.isAbsolute(f)).toBe(false);
  });

  it('ignores non-transcripts', () => {
    expect(found().some((f) => f.endsWith('.md'))).toBe(false);
  });

  it('returns nothing for a directory that does not exist', () => {
    expect(listSessionFiles(path.join(root, 'nope'))).toEqual([]);
  });

  it('stops at maxDepth rather than following a deep tree forever', () => {
    expect(listSessionFiles(path.join(root, 'proj'), 0)).toEqual(['sess-1.jsonl']);
  });
});

describe('sessionIdOf', () => {
  it('takes the basename, so a nested file is not given a session id with a separator', () => {
    // `file.replace(/\.jsonl$/, '')` on a nested path yields
    // "subagents/agent-x" — shipped to the cloud and used to group loops.
    expect(sessionIdOf(path.join('sess-1', 'subagents', 'agent-x.jsonl'))).toBe('agent-x');
  });

  it('is unchanged for a top-level file', () => {
    expect(sessionIdOf('sess-1.jsonl')).toBe('sess-1');
  });
});

describe('usageKey', () => {
  it('identifies a row by message id and request id together', () => {
    expect(usageKey({ message: { id: 'm1' }, requestId: 'r1' })).toBe('m1:r1');
  });

  it('returns null when either half is missing, so the caller can decide', () => {
    // 32 of 52,870 real rows. Dropping them silently would lose real spend;
    // the null makes that a caller's choice rather than an accident.
    expect(usageKey({ message: { id: 'm1' } })).toBeNull();
    expect(usageKey({ requestId: 'r1' })).toBeNull();
    expect(usageKey({})).toBeNull();
  });

  it('rejects non-string ids rather than coercing them into a key', () => {
    expect(usageKey({ message: { id: 7 }, requestId: 'r1' })).toBeNull();
    expect(usageKey({ message: { id: 'm1' }, requestId: '' })).toBeNull();
  });

  it('separates rows that share one half of the key', () => {
    expect(usageKey({ message: { id: 'm1' }, requestId: 'r1' })).not.toBe(
      usageKey({ message: { id: 'm1' }, requestId: 'r2' })
    );
  });
});
