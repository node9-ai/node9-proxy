/**
 * Unit tests for the MCP gateway's shell tokenizer.
 *
 * These tests verify that `tokenize()` correctly strips surrounding double-quotes
 * and preserves spaces within them — the property the integration tests rely on
 * when constructing `"${NODE}" "${upstreamScript}"` for --upstream.
 */

import { describe, it, expect } from 'vitest';
import { tokenize } from '../mcp-gateway/index';

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
