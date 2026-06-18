/**
 * Unit tests for renderOpencodeShim — the generator that produces the JS
 * plugin file written into ~/.config/opencode/plugins/node9.js by
 * setupOpencode.
 *
 * Why a separate file for the shim:
 *   - Opencode plugins live in user-owned directories with no node_modules
 *     resolution context, so the shim can't `import` types from
 *     @opencode-ai/plugin. We ship plain CommonJS JS.
 *   - The absolute path to the `node9` binary gets embedded at init time
 *     (resolved via process.argv[1]/process.execPath) so Opencode picking
 *     up an empty $PATH at launch doesn't break the shim.
 *
 * Pre-flight (verified against /home/nadav/node9/opensources/opencode-dev):
 *   - packages/opencode/src/plugin/loader.ts:138 does `await import(row.entry)`
 *     — Bun-native resolution handles .js files transparently
 *   - packages/opencode/src/plugin/shared.ts:272 (readV1Plugin) requires
 *     default export with `server` and/or `tui` keys
 *   - packages/opencode/src/config/plugin.ts:29 globs `*.{ts,js}` from
 *     `~/.config/opencode/{plugin,plugins}/`
 */
import { describe, it, expect } from 'vitest';
import { renderOpencodeShim } from '../setup-opencode-shim';

describe('renderOpencodeShim', () => {
  const baseInput = {
    node9Argv: ['/home/u/.nvm/versions/node/v22.0.0/bin/node9'],
    version: '1.25.0',
  };

  it('embeds the node9 argv array verbatim as a constant', () => {
    // The argv goes into spawnSync at runtime — Opencode's plugin
    // runtime inherits whatever $PATH was set at launch, which is often
    // a stripped shell. Embedding the resolved paths is the difference
    // between "node9 blocks bash" and "every tool silently slips
    // through with ENOENT".
    const out = renderOpencodeShim(baseInput);
    expect(out).toContain(`const NODE9_ARGV = ${JSON.stringify(baseInput.node9Argv)};`);
  });

  it('handles the dev-mode two-element argv ([node, cli.js])', () => {
    // npm-link / dev mode: process.argv[1] ends with .js, so
    // setupOpencode passes [process.execPath, cliJsPath]. The shim
    // invokes spawnSync(argv[0], [...argv.slice(1), "check"]).
    const out = renderOpencodeShim({
      node9Argv: ['/usr/bin/node', '/home/u/node9-proxy/dist/cli.js'],
      version: '1.25.0',
    });
    expect(out).toContain(
      'const NODE9_ARGV = ["/usr/bin/node","/home/u/node9-proxy/dist/cli.js"];'
    );
  });

  it('embeds the version constant for self-heal comparison', () => {
    // setupOpencode compares NODE9_SHIM_VERSION against the current
    // version on every init; mismatched shims get overwritten.
    const out = renderOpencodeShim(baseInput);
    expect(out).toContain('NODE9_SHIM_VERSION = "1.25.0"');
  });

  it('sets meta.agent to "Opencode" in every payload it sends to node9 check', () => {
    // detectAiAgent (check.ts) trusts payload.meta.agent. Without this
    // tag every Opencode hook would be misattributed to "Claude Code"
    // because the payload has hook_event_name: "PreToolUse".
    const out = renderOpencodeShim(baseInput);
    // Three hooks each set meta.agent; once is enough for the contract test.
    expect(out).toContain('agent: "Opencode"');
  });

  it('produces different content for different versions (so self-heal can detect change)', () => {
    const a = renderOpencodeShim({ ...baseInput, version: '1.25.0' });
    const b = renderOpencodeShim({ ...baseInput, version: '1.25.1' });
    expect(a).not.toBe(b);
  });

  it('exports a CommonJS module.exports with id and server keys', () => {
    // Pre-flight confirmed Opencode's plugin loader (readV1Plugin at
    // packages/opencode/src/plugin/shared.ts:272) requires `default
    // export an object with server()`. CommonJS module.exports is the
    // most portable form — works with Bun's native loader and any
    // package that imports the file as ESM (where module.exports
    // becomes the default export).
    const out = renderOpencodeShim(baseInput);
    expect(out).toContain('module.exports = {');
    expect(out).toContain('id: "node9"');
    expect(out).toMatch(/server:\s*async\s*\(/);
  });

  it('wires all three protection hooks (pre, post, prompt)', () => {
    // Pre-execution: block via throw
    // Post-execution: audit + gap1 output redaction
    // Chat message: prompt DLP (matches Claude's UserPromptSubmit)
    const out = renderOpencodeShim(baseInput);
    expect(out).toContain('"tool.execute.before"');
    expect(out).toContain('"tool.execute.after"');
    expect(out).toContain('"chat.message"');
  });

  it('wires gap1 Mode A redaction in the after-hook (receives output, redact round-trip, mutates)', () => {
    const out = renderOpencodeShim(baseInput);
    // The after-hook must take the second (output) arg, forward the output to
    // `log --redact-output`, and write the redacted text back into out.output.
    expect(out).toMatch(/"tool\.execute\.after":\s*async\s*\(ctx,\s*out\)/);
    expect(out).toContain('"log", "--redact-output"');
    expect(out).toContain('tool_response: { output: toolOutput }');
    expect(out).toContain('out.output = resp.redacted');
  });
});
