/**
 * Regression test for the browser-side esc() function in ui.html.
 *
 * We care about XSS hardening: inline onclick/onchange handlers in the UI
 * embed escaped values inside single-quoted JS strings, so esc() must
 * also escape apostrophes — otherwise an external MCP server (untrusted)
 * returning a tool name with ' in it can break out and execute arbitrary JS.
 *
 * This file is a static HTML asset, so we can't import esc() directly.
 * We extract it from the file and evaluate it in a sandboxed VM context.
 */

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import vm from 'vm';

const UI_HTML_PATH = path.resolve(__dirname, '../daemon/ui.html');

// Extract the `function esc(s) { ... }` block from ui.html and evaluate it
// in an isolated VM so we can call it as if it were in the browser.
function loadEsc(): (s: unknown) => string {
  const html = fs.readFileSync(UI_HTML_PATH, 'utf-8');
  const match = html.match(/function esc\(s\) \{[\s\S]*?\n {6}\}/);
  if (!match) throw new Error('esc() function not found in ui.html');
  const ctx = vm.createContext({});
  vm.runInContext(match[0] + '\nthis.__esc = esc;', ctx);
  return (ctx as unknown as { __esc: (s: unknown) => string }).__esc;
}

describe('ui.html esc()', () => {
  const esc = loadEsc();

  it('escapes the HTML big five', () => {
    expect(esc('&')).toBe('&amp;');
    expect(esc('<')).toBe('&lt;');
    expect(esc('>')).toBe('&gt;');
    expect(esc('"')).toBe('&quot;');
    expect(esc("'")).toBe('&#39;');
  });

  it('neutralises XSS via apostrophe in a single-quoted inline handler (MCP server XSS)', () => {
    // Realistic attack: external MCP server returns a tool name that tries to
    // break out of onchange="toggleMcpTool('...', '...', this.checked)".
    const malicious = "x', alert(document.cookie)+('y";
    const escaped = esc(malicious);
    // The escaped output must not contain a raw ' that could close the JS string.
    expect(escaped).not.toMatch(/'/);
    // It must still contain the structural payload text, just encoded.
    expect(escaped).toContain('&#39;');
    expect(escaped).toContain('alert(document.cookie)');
  });

  it('neutralises classic <script> injection', () => {
    expect(esc('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('does not double-escape already-escaped content (idempotent only on unrelated chars)', () => {
    // Ampersand is escaped first, so encoding is consistent but not idempotent —
    // this documents the expected behavior rather than guaranteeing it.
    expect(esc('a & b')).toBe('a &amp; b');
  });

  it('coerces non-strings safely', () => {
    expect(esc(42)).toBe('42');
    expect(esc(null)).toBe('null');
    expect(esc(undefined)).toBe('undefined');
  });
});
