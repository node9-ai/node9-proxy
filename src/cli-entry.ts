#!/usr/bin/env node
// src/cli-entry.ts -> dist/cli.js, the `node9` bin.
//
// Deliberately tiny: it only decides which bundle to load. `check` and `log`
// run as the PreToolUse / PostToolUse hooks on EVERY agent tool call, so they
// load the lean dist/cli-hook.js (policy + audit, none of the TUI, setup,
// scan, MCP gateway or prompt libraries). Every other command loads the full
// CLI in dist/cli-main.js. Import nothing here beyond node builtins: whatever
// this file pulls in is paid by every hook call.
// (Guarded by src/__tests__/cli-hook-entry.integration.test.ts.)
import path from 'path';
import module from 'module';

// Reuse V8's compiled code for the bundles across runs (Node >= 22.1; Node
// honors NODE_DISABLE_COMPILE_CACHE). Must run before the require below. Pure
// optimization: an older Node or an unwritable cache dir only loses the speedup.
try {
  module.enableCompileCache?.();
} catch {
  /* best effort, see above */
}

const sub = process.argv[2];
const bundle = sub === 'check' || sub === 'log' ? 'cli-hook.js' : 'cli-main.js';
// A runtime path on purpose: a literal specifier would make tsup inline the
// whole bundle into this file, which is exactly what the split avoids.
// eslint-disable-next-line @typescript-eslint/no-require-imports
require(path.join(__dirname, bundle));
