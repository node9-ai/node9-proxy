import { describe, it, expect } from 'vitest';
import { entryPathLabel } from '../cli/commands/scan';

describe('entryPathLabel', () => {
  it('maps tool-result → tool-output', () => {
    expect(entryPathLabel('tool-result')).toBe('tool-output');
  });

  it('maps user-prompt → user-prompt (preserved)', () => {
    expect(entryPathLabel('user-prompt')).toBe('user-prompt');
  });

  it('maps shell-config → shell-config (preserved)', () => {
    expect(entryPathLabel('shell-config')).toBe('shell-config');
  });

  it('maps real tool names (Bash, Read, Edit, Write) → tool-input', () => {
    expect(entryPathLabel('Bash')).toBe('tool-input');
    expect(entryPathLabel('Read')).toBe('tool-input');
    expect(entryPathLabel('Edit')).toBe('tool-input');
    expect(entryPathLabel('Write')).toBe('tool-input');
  });

  it('maps unknown / future tool names → tool-input (defensive default)', () => {
    expect(entryPathLabel('SomeNewTool')).toBe('tool-input');
    expect(entryPathLabel('mcp__github__create_pr')).toBe('tool-input');
    expect(entryPathLabel('')).toBe('tool-input');
  });
});
