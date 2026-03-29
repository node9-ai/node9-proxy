// src/__tests__/suggestion-tracker.spec.ts
// Unit tests for SuggestionTracker, extractPath, and commonPathPrefix.
import { describe, it, expect } from 'vitest';
import { SuggestionTracker, extractPath, commonPathPrefix } from '../daemon/suggestion-tracker.js';

// ── extractPath ────────────────────────────────────────────────────────────────

describe('extractPath', () => {
  it('returns null for non-object input', () => {
    expect(extractPath(null)).toBeNull();
    expect(extractPath('string')).toBeNull();
    expect(extractPath(42)).toBeNull();
  });

  it('extracts from "path" field', () => {
    expect(extractPath({ path: '/src/foo.ts' })).toBe('/src/foo.ts');
  });

  it('extracts from "file_path" field', () => {
    expect(extractPath({ file_path: '/src/bar.ts' })).toBe('/src/bar.ts');
  });

  it('extracts from "filename" field', () => {
    expect(extractPath({ filename: '/tmp/out.log' })).toBe('/tmp/out.log');
  });

  it('extracts from "filepath" field', () => {
    expect(extractPath({ filepath: '/a/b/c.txt' })).toBe('/a/b/c.txt');
  });

  it('extracts from "dest" field', () => {
    expect(extractPath({ dest: '/output/file.txt' })).toBe('/output/file.txt');
  });

  it('extracts from "destination" field', () => {
    expect(extractPath({ destination: '/output/file.txt' })).toBe('/output/file.txt');
  });

  it('returns null when no known path field exists', () => {
    expect(extractPath({ command: 'ls', cwd: '/tmp' })).toBeNull();
  });

  it('returns null for empty string path', () => {
    expect(extractPath({ path: '' })).toBeNull();
  });

  it('returns null when path field is a non-string (e.g. number)', () => {
    expect(extractPath({ path: 42 })).toBeNull();
  });

  it('returns null when path field is null', () => {
    expect(extractPath({ path: null })).toBeNull();
  });
});

// ── commonPathPrefix ───────────────────────────────────────────────────────────

describe('commonPathPrefix', () => {
  it('returns null for fewer than 2 paths', () => {
    expect(commonPathPrefix([])).toBeNull();
    expect(commonPathPrefix(['/src/foo.ts'])).toBeNull();
  });

  it('returns common directory for 2 paths in the same dir', () => {
    expect(commonPathPrefix(['/src/a/Button.tsx', '/src/a/Modal.tsx'])).toBe('/src/a/');
  });

  it('returns common ancestor for diverging subdirectories', () => {
    expect(commonPathPrefix(['/src/a/b/foo.ts', '/src/a/c/bar.ts'])).toBe('/src/a/');
  });

  it('returns null when no common prefix beyond root', () => {
    expect(commonPathPrefix(['/alpha/foo.ts', '/beta/bar.ts'])).toBeNull();
  });

  it('handles 3 paths correctly', () => {
    expect(
      commonPathPrefix(['/home/user/proj/a.ts', '/home/user/proj/b.ts', '/home/user/proj/c.ts'])
    ).toBe('/home/user/proj/');
  });

  it('returns null when one path is at root', () => {
    expect(commonPathPrefix(['/foo.ts', '/src/bar.ts'])).toBeNull();
  });
});

// ── SuggestionTracker ──────────────────────────────────────────────────────────

describe('SuggestionTracker', () => {
  it('returns null before threshold is reached', () => {
    const tracker = new SuggestionTracker(3);
    expect(tracker.recordAllow('Read', { path: '/src/a.ts' })).toBeNull();
    expect(tracker.recordAllow('Read', { path: '/src/b.ts' })).toBeNull();
    expect(tracker.getCount('Read')).toBe(2);
  });

  it('returns a Suggestion at exactly the threshold', () => {
    const tracker = new SuggestionTracker(3);
    tracker.recordAllow('Read', { path: '/src/a.ts' });
    tracker.recordAllow('Read', { path: '/src/b.ts' });
    const s = tracker.recordAllow('Read', { path: '/src/c.ts' });
    expect(s).not.toBeNull();
    expect(s!.toolName).toBe('Read');
    expect(s!.allowCount).toBe(3);
    expect(s!.status).toBe('pending');
  });

  it('resets counter after suggestion is generated', () => {
    const tracker = new SuggestionTracker(3);
    tracker.recordAllow('Read', { path: '/src/a.ts' });
    tracker.recordAllow('Read', { path: '/src/b.ts' });
    tracker.recordAllow('Read', { path: '/src/c.ts' });
    expect(tracker.getCount('Read')).toBe(0);
  });

  it('suggests a smartRule with path glob when paths share a common prefix', () => {
    const tracker = new SuggestionTracker(3);
    tracker.recordAllow('Write', { path: '/src/components/Button.tsx' });
    tracker.recordAllow('Write', { path: '/src/components/Modal.tsx' });
    const s = tracker.recordAllow('Write', { path: '/src/components/Input.tsx' });
    expect(s!.suggestedRule.type).toBe('smartRule');
    if (s!.suggestedRule.type === 'smartRule') {
      expect(s!.suggestedRule.rule.conditions[0].value).toBe('/src/components/**');
      expect(s!.suggestedRule.rule.verdict).toBe('allow');
      expect(s!.suggestedRule.rule.tool).toBe('Write');
    }
  });

  it('suggests ignoredTool when args have no path fields', () => {
    const tracker = new SuggestionTracker(3);
    tracker.recordAllow('Bash', { command: 'npm test' });
    tracker.recordAllow('Bash', { command: 'npm run lint' });
    const s = tracker.recordAllow('Bash', { command: 'npm run build' });
    expect(s!.suggestedRule.type).toBe('ignoredTool');
    if (s!.suggestedRule.type === 'ignoredTool') {
      expect(s!.suggestedRule.toolName).toBe('Bash');
    }
  });

  it('includes up to 3 exampleArgs in the suggestion', () => {
    const tracker = new SuggestionTracker(3);
    const args = [{ path: '/a.ts' }, { path: '/b.ts' }, { path: '/c.ts' }];
    for (const a of args) tracker.recordAllow('Read', a);
    // recordAllow returns null for first 2 and suggestion for 3rd — get it differently
    const tracker2 = new SuggestionTracker(3);
    tracker2.recordAllow('Read', args[0]);
    tracker2.recordAllow('Read', args[1]);
    const s = tracker2.recordAllow('Read', args[2]);
    expect(s!.exampleArgs).toHaveLength(3);
  });

  it('resetTool clears the count for a tool', () => {
    const tracker = new SuggestionTracker(3);
    tracker.recordAllow('Edit', { path: '/a.ts' });
    tracker.recordAllow('Edit', { path: '/b.ts' });
    expect(tracker.getCount('Edit')).toBe(2);
    tracker.resetTool('Edit');
    expect(tracker.getCount('Edit')).toBe(0);
  });

  it('does not cross-contaminate counts between tools', () => {
    const tracker = new SuggestionTracker(3);
    tracker.recordAllow('Read', { path: '/a.ts' });
    tracker.recordAllow('Write', { path: '/b.ts' });
    expect(tracker.getCount('Read')).toBe(1);
    expect(tracker.getCount('Write')).toBe(1);
  });

  it('works with threshold = 1', () => {
    const tracker = new SuggestionTracker(1);
    const s = tracker.recordAllow('Bash', { command: 'ls' });
    expect(s).not.toBeNull();
    expect(s!.toolName).toBe('Bash');
  });
});
