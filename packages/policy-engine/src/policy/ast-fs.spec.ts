// Hook-side AST FS-op detection + AST_FS_REGEX_RULES suppression.
// Step 0 of the canonical-extractor unification: bring scan.ts's AST tier
// into the engine's evaluatePolicy so live hook decisions match the CLI scan.
//
// These tests pin the behaviors the unification must guarantee:
//   1. The engine waterfall blocks `cat ~/.ssh/id_rsa` for AI agents WITHOUT
//      relying on the project-jail regex smart rule — i.e. AST alone does it.
//   2. AST suppresses regex FPs the existing normalizeCommandForPolicy doesn't
//      catch. Specifically: `echo '{"command":"cat ~/.ssh/id_rsa"}'` — the
//      JSON arg is not a quoted shell string, so normalize keeps it; the regex
//      matches; AST sees CallExpr name is `echo` and returns null. Without
//      AST_FS_REGEX_RULES suppression the regex rule blocks (FP).
//   3. AST is skipped for manual humans (agent === 'Terminal') — node9 is
//      AI-driven and we trust the user when they're typing themselves.
//   4. AST tier fires for all six agent bash tool names
//      (bash, execute_bash, run_shell_command, shell, exec_command).

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import projectJail from '../shields/builtin/project-jail.json';
import type { SmartRule } from '../types';

// Config WITHOUT smart rules — proves the AST tier alone produces the verdict.
const astOnlyConfig: PolicyConfig = {
  policy: {
    sandboxPaths: [],
    dangerousWords: [],
    ignoredTools: [],
    toolInspection: {
      bash: 'command',
      execute_bash: 'command',
      run_shell_command: 'command',
      shell: 'command',
      exec_command: 'command',
    },
    smartRules: [],
    dlp: { enabled: false, scanIgnoredTools: false },
  },
  settings: { mode: 'standard' },
};

// Config WITH the project-jail shield rules — proves the AST tier suppresses
// the regex rules whose names appear in AST_FS_REGEX_RULES.
const shieldedConfig: PolicyConfig = {
  ...astOnlyConfig,
  policy: {
    ...astOnlyConfig.policy,
    smartRules: projectJail.smartRules as SmartRule[],
  },
};

describe('Hook-side AST FS-op detection (Step 0)', () => {
  it('blocks `cat ~/.ssh/id_rsa` via AST tier alone (no smart rules)', async () => {
    const r = await evaluatePolicy(
      astOnlyConfig,
      'bash',
      { command: 'cat ~/.ssh/id_rsa' },
      { agent: 'claude' }
    );
    expect(r.decision).toBe('block');
    expect(r.ruleName).toBe('shield:project-jail:block-read-ssh');
  });

  it('blocks `cat ~/.aws/credentials` via AST tier alone', async () => {
    const r = await evaluatePolicy(
      astOnlyConfig,
      'bash',
      { command: 'cat ~/.aws/credentials' },
      { agent: 'claude' }
    );
    expect(r.decision).toBe('block');
    expect(r.ruleName).toBe('shield:project-jail:block-read-aws');
  });

  it('suppresses regex FP that normalizeCommandForPolicy misses (JSON arg with cat ~/.ssh/)', async () => {
    // The single-quoted JSON `'{"command":"cat ~/.ssh/id_rsa"}'` is a literal
    // arg to `echo`, not a shell command. normalizeCommandForPolicy doesn't
    // strip it (no quoted-message flag like -m precedes it), so the regex
    // matches `cat ~/.ssh/`. AST sees the CallExpr name is `echo`, returns
    // null, and AST_FS_REGEX_RULES suppression must fire to clear the FP.
    const r = await evaluatePolicy(
      shieldedConfig,
      'bash',
      { command: `echo '{"command":"cat ~/.ssh/id_rsa"}'` },
      { agent: 'claude' }
    );
    expect(r.decision).toBe('allow');
  });

  it('does NOT run AST for agent === "Terminal" (manual humans pass through)', async () => {
    // Without shield rules in config and AST disabled for Terminal, the
    // dangerous command falls through to the manual auto-allow at tier 4.
    const r = await evaluatePolicy(
      astOnlyConfig,
      'bash',
      { command: 'cat ~/.ssh/id_rsa' },
      { agent: 'Terminal' }
    );
    expect(r.decision).toBe('allow');
  });

  it('AST tier fires on gemini run_shell_command', async () => {
    const r = await evaluatePolicy(
      astOnlyConfig,
      'run_shell_command',
      { command: 'cat ~/.ssh/id_rsa' },
      { agent: 'gemini' }
    );
    expect(r.decision).toBe('block');
  });

  it('AST tier fires on codex exec_command', async () => {
    const r = await evaluatePolicy(
      astOnlyConfig,
      'exec_command',
      { command: 'cat ~/.ssh/id_rsa' },
      { agent: 'codex' }
    );
    expect(r.decision).toBe('block');
  });

  it('benign bash command still allowed (no AST verdict, no smart-rule match)', async () => {
    const r = await evaluatePolicy(
      astOnlyConfig,
      'bash',
      { command: 'ls -la' },
      { agent: 'claude' }
    );
    expect(r.decision).toBe('allow');
  });
});
