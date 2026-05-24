/**
 * Unit tests for renderPiShim — the generator that produces the JS
 * extension file written into ~/.pi/agent/extensions/node9.js by
 * setupPi.
 *
 * Why a separate file for the shim (same reasoning as opencode):
 *   - Pi extensions live in user-owned directories with no node_modules
 *     resolution context, so the shim can't `import` types from
 *     @earendil-works/pi-coding-agent. We ship plain CommonJS JS.
 *   - The absolute path to the `node9` binary gets embedded at init time
 *     (resolved via process.argv[1]/process.execPath) so Pi picking up
 *     an empty $PATH at launch doesn't break the shim.
 *
 * Pre-flight (verified against /home/nadav/node9/opensources/pi-main):
 *   - packages/coding-agent/src/core/extensions/loader.ts globs
 *     `extensions/*.ts` or `*.js` under `<cwd>/.pi/extensions/` and
 *     `~/.pi/agent/extensions/` (the latter is our install target).
 *   - packages/coding-agent/src/core/extensions/types.ts: hook events
 *     are `tool_call` (can return { block: true, reason }), `tool_result`
 *     (audit), `input` (returns { action: "continue"|"transform"|"handled" }),
 *     and `user_bash` (the !/!! prompt-escape side channel — design R4).
 *   - Pi tool names are lowercase (`bash`, `read`, `edit`, `write`,
 *     `grep`, `find`, `ls`) — they must be normalized to the PascalCase
 *     names node9's policy engine matches against (design R5).
 */
import { describe, it, expect } from 'vitest';
import { renderPiShim } from '../setup-pi-shim';

describe('renderPiShim', () => {
  const baseInput = {
    node9Argv: ['/home/u/.nvm/versions/node/v22.0.0/bin/node9'],
    version: '1.26.1',
  };

  it('embeds the node9 argv array verbatim as a constant', () => {
    // Same reasoning as opencode: pi extension runtime inherits whatever
    // $PATH was set at launch. Embedding the resolved path is the
    // difference between "node9 blocks bash" and "every tool silently
    // slips through with ENOENT".
    const out = renderPiShim(baseInput);
    expect(out).toContain(`const NODE9_ARGV = ${JSON.stringify(baseInput.node9Argv)};`);
  });

  it('handles the dev-mode two-element argv ([node, cli.js])', () => {
    const out = renderPiShim({
      node9Argv: ['/usr/bin/node', '/home/u/node9-proxy/dist/cli.js'],
      version: '1.26.1',
    });
    expect(out).toContain(
      'const NODE9_ARGV = ["/usr/bin/node","/home/u/node9-proxy/dist/cli.js"];'
    );
  });

  it('embeds the version constant for self-heal comparison', () => {
    // setupPi compares NODE9_SHIM_VERSION against the current version on
    // every init; mismatched shims get overwritten.
    const out = renderPiShim(baseInput);
    expect(out).toContain('NODE9_SHIM_VERSION = "1.26.1"');
  });

  it('sets meta.agent to "Pi" in every payload it sends to node9 check', () => {
    // detectAiAgent (check.ts) routes payload.meta.agent through the
    // Layer-0 generic branch (see detect-ai-agent.spec.ts:54). Without
    // this tag, Pi's pre-tool payloads would be misattributed to "Claude
    // Code" because they carry hook_event_name: "PreToolUse".
    const out = renderPiShim(baseInput);
    expect(out).toContain('agent: "Pi"');
  });

  it('produces different content for different versions (so self-heal can detect change)', () => {
    const a = renderPiShim({ ...baseInput, version: '1.26.1' });
    const b = renderPiShim({ ...baseInput, version: '1.26.2' });
    expect(a).not.toBe(b);
  });

  it('exports a CommonJS module.exports with default-export factory shape', () => {
    // Pi's loader uses jiti (loader.ts) which handles CommonJS interop —
    // a `module.exports = function (pi) { ... }` is the most portable
    // form across Node and the Bun-compiled binary path (design R2).
    const out = renderPiShim(baseInput);
    expect(out).toContain('module.exports');
    // Default-exported factory takes the ExtensionAPI parameter
    expect(out).toMatch(/function\s*\(\s*pi\s*\)/);
  });

  it('wires all four protection hooks (tool_call, tool_result, input, user_bash)', () => {
    // tool_call:   PreToolUse equivalent (block via return value)
    // tool_result: PostToolUse fire-and-forget audit
    // input:       UserPromptSubmit equivalent (DLP scan)
    // user_bash:   the !/!! prompt-escape side channel (design R4) —
    //              forgetting this is a silent DLP bypass.
    const out = renderPiShim(baseInput);
    expect(out).toContain('"tool_call"');
    expect(out).toContain('"tool_result"');
    expect(out).toContain('"input"');
    expect(out).toContain('"user_bash"');
  });

  it('tool_call handler blocks via { block: true, reason } return (not throw)', () => {
    // Pi's tool_call contract is RETURN { block: true, reason } — NOT
    // throw (which is opencode's contract). Verified against
    // pi-main/packages/coding-agent/examples/extensions/permission-gate.ts:23
    // which uses `return { block: true, reason: "..." };`.
    const out = renderPiShim(baseInput);
    expect(out).toMatch(/return\s*\{\s*block:\s*true/);
  });

  it('input handler uses { action: "handled" } for DLP block (per pi InputEventResult)', () => {
    // From types.ts:762 — InputEventResult is one of:
    //   { action: "continue" } | { action: "transform"; text; images? } | { action: "handled" }
    // Block path is "handled" (suppress). "continue" is allow.
    const out = renderPiShim(baseInput);
    expect(out).toMatch(/action:\s*"handled"/);
  });

  it('normalizes pi lowercase tool names to PascalCase before sending to node9 check', () => {
    // Design R5: pi uses `bash`/`read`/`edit`/`write`/`grep`/`find`/`ls`;
    // the policy engine matches against PascalCase from Claude (`Bash`,
    // `Read`, etc.). Without normalization, every DLP/jail rule silently
    // no-ops on pi payloads.
    //
    // We check the rendered shim contains a mapping table that includes
    // at least the four load-bearing tools — bash/read/write/edit.
    const out = renderPiShim(baseInput);
    expect(out).toContain('bash');
    expect(out).toContain('Bash');
    expect(out).toContain('read');
    expect(out).toContain('Read');
    expect(out).toContain('write');
    expect(out).toContain('Write');
    expect(out).toContain('edit');
    expect(out).toContain('Edit');
  });

  it('user_bash hook sends a Bash-shaped PreToolUse payload (so policy rules engage)', () => {
    // user_bash event has `{ command, excludeFromContext, cwd }` — no
    // `tool_name`. The shim must synthesize tool_name: "Bash" +
    // tool_input: { command } so existing dangerous-words rules apply
    // exactly as they would to a tool_call(bash). This is the R4
    // mitigation in code.
    const out = renderPiShim(baseInput);
    // The user_bash handler block must reference Bash (PascalCase) and
    // the synthetic PreToolUse shape.
    expect(out).toMatch(/tool_name:\s*"Bash"/);
  });
});
