// src/__tests__/hook-payload.spec.ts
// Unit tests for utils/hook-payload.ts
import { describe, it, expect } from 'vitest';
import { extractToolName, extractToolInput } from '../utils/hook-payload.js';

describe('extractToolName', () => {
  it('returns tool_name when present (Claude shape)', () => {
    expect(extractToolName({ tool_name: 'Bash' })).toBe('Bash');
  });

  it('returns name when only Gemini shape is present', () => {
    expect(extractToolName({ name: 'run_shell_command' })).toBe('run_shell_command');
  });

  it('prefers tool_name over name when both are present', () => {
    expect(extractToolName({ tool_name: 'Bash', name: 'should_not_win' })).toBe('Bash');
  });

  it('returns empty string by default when no field is present', () => {
    expect(extractToolName({})).toBe('');
  });

  it('returns supplied defaultValue when no field is present', () => {
    expect(extractToolName({}, 'unknown')).toBe('unknown');
  });

  it('treats explicit empty string as the value (not as missing)', () => {
    // tool_name is set, just empty — `??` only triggers on null/undefined,
    // so the empty string wins over the default. Matches the existing
    // inline pattern in check.ts and log.ts pre-refactor.
    expect(extractToolName({ tool_name: '' }, 'fallback')).toBe('');
  });

  it('falls back across null tool_name to name', () => {
    // Defensive: typed as undefined, but real-world payloads occasionally
    // serialise `null`. `??` handles both.
    const payload = { tool_name: null as unknown as undefined, name: 'gemini_tool' };
    expect(extractToolName(payload)).toBe('gemini_tool');
  });
});

describe('extractToolInput', () => {
  it('returns tool_input when present (Claude shape)', () => {
    expect(extractToolInput({ tool_input: { command: 'ls' } })).toEqual({ command: 'ls' });
  });

  it('returns args when only Gemini shape is present', () => {
    expect(extractToolInput({ args: { command: 'ls' } })).toEqual({ command: 'ls' });
  });

  it('prefers tool_input over args when both are present', () => {
    expect(extractToolInput({ tool_input: { winner: true }, args: { winner: false } })).toEqual({
      winner: true,
    });
  });

  it('returns empty object when no field is present', () => {
    expect(extractToolInput({})).toEqual({});
  });

  it('preserves non-object input values verbatim (no type coercion)', () => {
    // tool_input is `unknown` — callers handle non-object cases themselves.
    expect(extractToolInput({ tool_input: 'a string' })).toBe('a string');
    expect(extractToolInput({ tool_input: 42 })).toBe(42);
    expect(extractToolInput({ tool_input: null })).toEqual({});
  });
});
