import { describe, it, expect } from 'vitest';
import { stripTerminalEscapes } from '../cli/commands/scan';

describe('stripTerminalEscapes', () => {
  it('passes plain text through unchanged', () => {
    expect(stripTerminalEscapes('git push origin main')).toBe('git push origin main');
  });

  it('preserves common whitespace (TAB, LF, CR)', () => {
    expect(stripTerminalEscapes('a\tb\nc\rd')).toBe('a\tb\nc\rd');
  });

  it('strips CSI sequences (clear-screen, cursor-move, color)', () => {
    expect(stripTerminalEscapes('\x1b[2Jhi')).toBe('hi');
    expect(stripTerminalEscapes('\x1b[31mred\x1b[0m')).toBe('red');
    expect(stripTerminalEscapes('\x1b[1;32;40mtext\x1b[0m')).toBe('text');
  });

  it('strips OSC sequences (set window title) terminated by BEL', () => {
    expect(stripTerminalEscapes('\x1b]0;malicious\x07command')).toBe('command');
  });

  it('strips OSC sequences terminated by ST (ESC \\)', () => {
    expect(stripTerminalEscapes('\x1b]0;evil\x1b\\command')).toBe('command');
  });

  it('strips lone ESC bytes', () => {
    expect(stripTerminalEscapes('\x1bA')).toBe('');
  });

  it('strips C0 control characters except whitespace + DEL', () => {
    // \x00 NUL, \x01 SOH, \x07 BEL, \x08 BS, \x7f DEL — all should go
    expect(stripTerminalEscapes('a\x00b\x01c\x07d\x08e\x7ff')).toBe('abcdef');
  });

  it('handles a realistic terminal-injection payload', () => {
    // AI agent embeds: "rm -rf /tmp\x1b]0;safe\x07\x1b[31mFAKE PROMPT$\x1b[0m"
    const input = 'rm -rf /tmp\x1b]0;safe\x07\x1b[31mFAKE PROMPT$\x1b[0m';
    expect(stripTerminalEscapes(input)).toBe('rm -rf /tmpFAKE PROMPT$');
  });

  it('returns empty string for input made entirely of escapes', () => {
    expect(stripTerminalEscapes('\x1b[2J\x1b[0m\x07\x00')).toBe('');
  });
});
