/**
 * Unit tests for the MCP gateway's shell tokenizer.
 *
 * These tests verify that `tokenize()` correctly strips surrounding double-quotes
 * and preserves spaces within them — the property the integration tests rely on
 * when constructing `"${NODE}" "${upstreamScript}"` for --upstream.
 */

import { describe, it, expect } from 'vitest';
import { tokenize, normalizeClientName } from '../mcp-gateway/index';

describe('tokenize', () => {
  it('splits on whitespace', () => {
    expect(tokenize('node server.js')).toEqual(['node', 'server.js']);
  });

  it('strips surrounding double-quotes and preserves spaces inside', () => {
    expect(tokenize('node "/path with spaces/server.js"')).toEqual([
      'node',
      '/path with spaces/server.js',
    ]);
  });

  it('strips quotes from both tokens (NODE + path pattern used in tests)', () => {
    expect(tokenize('"/usr/bin/node" "/tmp/my dir/upstream.js"')).toEqual([
      '/usr/bin/node',
      '/tmp/my dir/upstream.js',
    ]);
  });

  it('handles backslash escapes inside quotes', () => {
    expect(tokenize('"path\\"with\\"quotes"')).toEqual(['path"with"quotes']);
  });

  it('handles backslash escapes outside quotes', () => {
    expect(tokenize('node path\\ with\\ spaces')).toEqual(['node', 'path with spaces']);
  });

  it('handles multiple args without quotes', () => {
    expect(tokenize('npx -y @scope/pkg .')).toEqual(['npx', '-y', '@scope/pkg', '.']);
  });

  it('returns empty array for empty string', () => {
    expect(tokenize('')).toEqual([]);
  });

  it('handles leading/trailing whitespace', () => {
    expect(tokenize('  node  server.js  ')).toEqual(['node', 'server.js']);
  });

  it('drops empty-string token from adjacent quotes (no real command needs empty tokens)', () => {
    expect(tokenize('node "" arg')).toEqual(['node', 'arg']);
  });
});

describe('normalizeClientName', () => {
  it('maps known clients to canonical labels', () => {
    expect(normalizeClientName('claude-ai')).toBe('Claude');
    expect(normalizeClientName('Claude Code')).toBe('Claude');
    expect(normalizeClientName('cursor')).toBe('Cursor');
    expect(normalizeClientName('Cursor 0.42')).toBe('Cursor');
    expect(normalizeClientName('codex-cli')).toBe('Codex');
    expect(normalizeClientName('gemini-cli')).toBe('Gemini');
    expect(normalizeClientName('cline')).toBe('Cline');
    expect(normalizeClientName('continue')).toBe('Continue');
  });

  it('returns undefined for missing or non-string input', () => {
    expect(normalizeClientName(undefined)).toBeUndefined();
    expect(normalizeClientName(null)).toBeUndefined();
    expect(normalizeClientName('')).toBeUndefined();
    expect(normalizeClientName(42)).toBeUndefined();
    expect(normalizeClientName({ name: 'claude' })).toBeUndefined();
  });

  it('preserves unknown clients but sanitizes and caps length', () => {
    expect(normalizeClientName('weird-client-1.0')).toBe('weird-client-1.0');
    expect(normalizeClientName('a'.repeat(80))).toBe('a'.repeat(40));
  });

  it('strips control characters from unknown client names', () => {
    expect(normalizeClientName('weird\x00\x07client')).toBe('weirdclient');
  });

  it('returns undefined when sanitizing leaves nothing', () => {
    expect(normalizeClientName('\x00\x01\x02')).toBeUndefined();
  });
});
