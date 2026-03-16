import { describe, it, expect } from 'vitest';
import { extractContext, smartTruncate, computeRiskMetadata } from '../context-sniper.js';

// ── smartTruncate ─────────────────────────────────────────────────────────────

describe('smartTruncate', () => {
  it('returns the string unchanged when it is within the limit', () => {
    const s = 'hello world';
    expect(smartTruncate(s, 500)).toBe(s);
  });

  it('returns the string unchanged when it is exactly the limit', () => {
    const s = 'a'.repeat(500);
    expect(smartTruncate(s, 500)).toBe(s);
  });

  it('truncates long strings and inserts " ... " in the middle', () => {
    const s = 'a'.repeat(600);
    const result = smartTruncate(s, 500);
    expect(result).toContain(' ... ');
    expect(result.length).toBeLessThan(s.length);
  });

  it('keeps the start and end of a long string', () => {
    const s = 'START' + 'x'.repeat(600) + 'END';
    const result = smartTruncate(s, 500);
    expect(result.startsWith('START')).toBe(true);
    expect(result.endsWith('END')).toBe(true);
  });

  it('uses 500 as the default maxLen', () => {
    const s = 'x'.repeat(600);
    const result = smartTruncate(s);
    expect(result).toContain(' ... ');
  });
});

// ── extractContext ────────────────────────────────────────────────────────────

describe('extractContext', () => {
  /** Build a string with N lines, each being "line_N". */
  function makeLines(count: number): string {
    return Array.from({ length: count }, (_, i) => `line_${i + 1}`).join('\n');
  }

  it('returns full text when it has 7 or fewer lines', () => {
    const text = makeLines(7);
    const { snippet, lineIndex } = extractContext(text, 'line_4');
    expect(snippet).toBe(text);
    expect(lineIndex).toBe(-1);
  });

  it('returns full text (truncated) when no matchedWord is given', () => {
    const text = makeLines(20);
    const { lineIndex } = extractContext(text);
    expect(lineIndex).toBe(-1);
  });

  it('returns a 7-line window centred on the matched word', () => {
    const text = makeLines(20); // "line_1\nline_2\n..."
    // 'line_10' is at index 9 (0-based); window should be 7 content lines
    const { snippet } = extractContext(text, 'line_10');
    // Content lines contain 'line_N'; head/tail markers contain 'hidden'
    const contentLines = snippet.split('\n').filter((l) => l.includes('line_'));
    expect(contentLines.length).toBe(7);
    expect(contentLines.some((l) => l.includes('line_10'))).toBe(true);
  });

  it('marks the hit line with the 🛑 emoji', () => {
    const text = makeLines(20);
    const { snippet } = extractContext(text, 'line_10');
    // The 🛑 marker should appear exactly once on the hit line
    const markedLine = snippet.split('\n').find((l) => l.startsWith('🛑'));
    expect(markedLine).toBeDefined();
    expect(markedLine).toContain('line_10');
  });

  it('lineIndex is the 0-based offset of the hit line within the extracted window', () => {
    const text = makeLines(20);
    const { snippet, lineIndex } = extractContext(text, 'line_15');
    // lineIndex is relative to the content window (head prefix is separate).
    // The content window lines are those that include 'line_' (not the head/tail markers).
    expect(lineIndex).toBeGreaterThanOrEqual(0);
    const windowLines = snippet.split('\n').filter((l) => l.includes('line_'));
    expect(windowLines[lineIndex]).toContain('line_15');
    expect(windowLines[lineIndex].startsWith('🛑')).toBe(true);
  });

  it('clamps window to the start of the text (hit near the top)', () => {
    const text = makeLines(20);
    const { snippet } = extractContext(text, 'line_2');
    // Window starts at line_1 (no lines before line_2 to show 3 above)
    expect(snippet).toContain('line_1');
    expect(snippet).not.toContain('... [0 lines hidden]');
  });

  it('clamps window to the end of the text (hit near the bottom)', () => {
    const text = makeLines(20);
    const { snippet } = extractContext(text, 'line_20');
    expect(snippet).toContain('line_20');
  });

  it('prefers a non-comment line over a comment line with the same word', () => {
    const lines = [
      '// rm -rf is dangerous', // comment hit
      'const x = 1;',
      'const y = 2;',
      'const z = 3;',
      'const a = 4;',
      'const b = 5;',
      'const c = 6;',
      'const d = 7;',
      'exec("rm -rf /tmp/old")', // non-comment hit — should be preferred
    ];
    const text = lines.join('\n');
    const { snippet } = extractContext(text, 'rm');
    // The 🛑 line should contain the exec call, not the comment
    const markedLine = snippet.split('\n').find((l) => l.startsWith('🛑'));
    expect(markedLine).toBeDefined();
    expect(markedLine).toContain('exec');
  });

  it('falls back to first hit if all occurrences are in comments', () => {
    const lines = [
      '// rm is bad',
      '// rm should be avoided',
      'const x = 1;',
      'const y = 2;',
      'const z = 3;',
      'const a = 4;',
      'const b = 5;',
      'const c = 6;',
      'const d = 7;',
    ];
    const text = lines.join('\n');
    const { snippet } = extractContext(text, 'rm');
    const markedLine = snippet.split('\n').find((l) => l.startsWith('🛑'));
    expect(markedLine).toBeDefined();
    // Falls back to the first hit (line 0 — the comment)
    expect(markedLine).toContain('rm is bad');
  });

  it('returns full text when word is not found in any line', () => {
    const text = makeLines(20);
    const { lineIndex } = extractContext(text, 'nonexistent_xyz');
    expect(lineIndex).toBe(-1);
  });

  it('adds head/tail markers when window is in the middle of a long text', () => {
    const text = makeLines(30);
    // Hit is in the middle — there will be hidden lines above and below
    const { snippet } = extractContext(text, 'line_15');
    expect(snippet).toContain('lines hidden');
  });
});

// ── computeRiskMetadata ───────────────────────────────────────────────────────

describe('computeRiskMetadata', () => {
  it('returns EXEC intent by default when no old_string/new_string', () => {
    const meta = computeRiskMetadata({ command: 'sudo rm -rf /' }, 6, 'dangerous word: rm');
    expect(meta.intent).toBe('EXEC');
  });

  it('returns EDIT intent when args has old_string and new_string', () => {
    const meta = computeRiskMetadata(
      { old_string: 'foo', new_string: 'bar', file_path: 'src/app.ts' },
      5,
      'project rule'
    );
    expect(meta.intent).toBe('EDIT');
  });

  it('sets editFileName and editFilePath for EDIT intent', () => {
    const meta = computeRiskMetadata(
      { old_string: 'a', new_string: 'b', file_path: '/home/user/src/app.ts' },
      5,
      'rule'
    );
    expect(meta.editFilePath).toBe('/home/user/src/app.ts');
    expect(meta.editFileName).toBe('app.ts');
  });

  it('includes tier and blockedByLabel in all cases', () => {
    const meta = computeRiskMetadata({ command: 'drop' }, 6, 'dangerous: drop');
    expect(meta.tier).toBe(6);
    expect(meta.blockedByLabel).toBe('dangerous: drop');
  });

  it('includes matchedWord when provided', () => {
    const meta = computeRiskMetadata({ command: 'mkfs /dev/sdb' }, 6, 'label', undefined, 'mkfs');
    expect(meta.matchedWord).toBe('mkfs');
  });

  it('includes matchedField when provided', () => {
    const meta = computeRiskMetadata({ command: 'x' }, 6, 'label', 'command');
    expect(meta.matchedField).toBe('command');
  });

  it('includes ruleName when provided', () => {
    const meta = computeRiskMetadata(
      {},
      2,
      'Smart Rule: block-force-push',
      undefined,
      undefined,
      'block-force-push'
    );
    expect(meta.ruleName).toBe('block-force-push');
  });

  it('extracts contextSnippet from matchedField for EXEC intent', () => {
    const meta = computeRiskMetadata(
      { command: 'sudo rm -rf /var' },
      6,
      'label',
      'command',
      'sudo'
    );
    expect(meta.contextSnippet).toBeDefined();
    expect(meta.contextSnippet).toContain('sudo');
  });

  it('falls back to first code-like key when matchedField is absent', () => {
    const meta = computeRiskMetadata({ command: 'ls -la' }, 6, 'label');
    // 'command' is in CODE_KEYS — should be picked up as the context source
    expect(meta.contextSnippet).toBeDefined();
    expect(meta.contextSnippet).toContain('ls -la');
  });

  it('handles Gemini-style stringified JSON args', () => {
    const stringifiedArgs = JSON.stringify({ command: 'mkfs /dev/sdb' });
    const meta = computeRiskMetadata(stringifiedArgs, 6, 'label', 'command', 'mkfs');
    expect(meta.contextSnippet).toBeDefined();
    expect(meta.contextSnippet).toContain('mkfs');
  });

  it('handles string args that are not JSON', () => {
    const meta = computeRiskMetadata('plain string args', 6, 'label');
    expect(meta.contextSnippet).toBe('plain string args');
  });

  it('omits optional fields when not provided', () => {
    const meta = computeRiskMetadata({}, 3, 'inline exec');
    expect(meta.matchedWord).toBeUndefined();
    expect(meta.matchedField).toBeUndefined();
    expect(meta.ruleName).toBeUndefined();
    expect(meta.contextLineIndex).toBeUndefined();
  });
});
