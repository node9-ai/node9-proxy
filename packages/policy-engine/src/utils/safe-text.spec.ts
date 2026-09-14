import { describe, it, expect } from 'vitest';
import { stripTerminalEscapes, stripControlChars, safeMessage } from './safe-text';

// A forged "success" line: CR to return to column 0, SGR green, fake text.
const FORGED_LINE = '\x1b[32m OK Cloud: connected and governed\x1b[0m';

describe('stripTerminalEscapes', () => {
  it('leaves ordinary text alone', () => {
    expect(stripTerminalEscapes('git push origin main')).toBe('git push origin main');
  });

  it('KEEPS tab, newline and carriage return', () => {
    // A later .replace(/\s+/g, ' ') collapses these. Removing them here would
    // run words together, which is exactly what stripControlChars does.
    expect(stripTerminalEscapes('a\tb\nc\rd')).toBe('a\tb\nc\rd');
  });

  it('removes CSI, OSC and Fe sequences', () => {
    expect(stripTerminalEscapes('\x1b[31mred\x1b[0m')).toBe('red');
    expect(stripTerminalEscapes('\x1b]0;malicious\x07command')).toBe('command');
    expect(stripTerminalEscapes('\x1b]0;evil\x1b\\command')).toBe('command');
    expect(stripTerminalEscapes('\x1bA')).toBe('');
  });

  it('removes C0 controls other than whitespace, and DEL', () => {
    expect(stripTerminalEscapes('a\x00b\x01c\x07d\x08e\x7ff')).toBe('abcdef');
  });

  it('defuses a forged terminal line', () => {
    expect(stripTerminalEscapes(FORGED_LINE)).toBe(' OK Cloud: connected and governed');
  });
});

describe('stripControlChars', () => {
  it('removes every C0 control and DEL, whitespace included', () => {
    expect(stripControlChars('a\tb\nc\rd')).toBe('abcd');
    expect(stripControlChars('Bash\x00\x1b[31m')).toBe('Bash[31m');
  });

  it('leaves ordinary text alone', () => {
    expect(stripControlChars('mcp__server__write_file')).toBe('mcp__server__write_file');
  });
});

describe('the three are deliberately different', () => {
  // This is the guard that stops a future "let us just use one of these".
  // Flattening Group B onto Group A merges words in every scan preview.
  it('differs on whitespace in the way the callers depend on', () => {
    const input = 'alpha\nbeta\ttail';
    expect(stripTerminalEscapes(input)).toBe('alpha\nbeta\ttail');
    expect(stripTerminalEscapes(input).replace(/\s+/g, ' ')).toBe('alpha beta tail');
    expect(stripControlChars(input)).toBe('alphabetatail');
  });

  it('differs on non-whitespace C0 controls', () => {
    const input = 'a\x07b';
    expect(stripTerminalEscapes(input)).toBe('ab');
    expect(stripControlChars(input)).toBe('ab');
  });
});

describe('safeMessage', () => {
  it('cannot forge a second terminal line', () => {
    // The attack: CR returns the cursor to column 0, then green SGR paints a
    // line that looks like one of ours.
    const hostile = 'timeout\r\x1b[32m OK Cloud: connected and governed\x1b[0m';
    const out = safeMessage(hostile);
    expect(out).toBe('timeout OK Cloud: connected and governed');
    expect(out).not.toContain('\r');
    expect(out).not.toContain('\x1b');
  });

  it('cannot forge a second log entry', () => {
    const hostile = 'boom\n[2026-09-14T00:00:00.000Z] ALLOW everything';
    expect(safeMessage(hostile)).not.toContain('\n');
  });

  it('collapses every run of whitespace to one space', () => {
    expect(safeMessage('a \t\n\r  b')).toBe('a b');
  });

  it('caps length so a peer cannot flood the log', () => {
    const out = safeMessage('x'.repeat(5000));
    expect(out.length).toBe(300);
    expect(out.endsWith('\u2026')).toBe(true);
  });

  it('honours a custom cap', () => {
    expect(safeMessage('x'.repeat(100), 10).length).toBe(10);
  });

  it('accepts an Error, a non-string, null and undefined', () => {
    expect(safeMessage(new Error('bad\nthing'))).toBe('bad thing');
    expect(safeMessage(42)).toBe('42');
    expect(safeMessage(null)).toBe('');
    expect(safeMessage(undefined)).toBe('');
  });

  it('leaves an ordinary message untouched', () => {
    expect(safeMessage('Server returned HTTP 503.')).toBe('Server returned HTTP 503.');
  });
});
