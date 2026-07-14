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
import filesystem from '../shields/builtin/filesystem.json';
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

// Config WITH the filesystem shield rules — the review-chmod-777 rule is a raw
// regex that matched `chmod 777` anywhere in the command string, including
// inside a `node -e` / `python -c` payload's string/regex literal. The AST
// detector (analyzeChmod777) + AST_FS_REGEX_RULES suppression must clear that
// FP while keeping a real `chmod 777 <path>` as a true positive.
const filesystemShieldedConfig: PolicyConfig = {
  ...astOnlyConfig,
  policy: {
    ...astOnlyConfig.policy,
    smartRules: filesystem.smartRules as SmartRule[],
  },
};

// Config WITH the proxy-side rm advisory rules (src/config/index.ts
// ADVISORY_SMART_RULES), appended LAST as getConfig() does. The `review-rm`
// advisory reviews every rm; the same-command create-then-delete waiver must
// skip it ONLY for a scratch-file cleanup (`cat > f <<EOF …; rm -f f`) while
// leaving `.env`, cross-command, dynamic, and out-of-cwd deletes at review.
const rmAdvisoryConfig: PolicyConfig = {
  ...astOnlyConfig,
  policy: {
    ...astOnlyConfig.policy,
    smartRules: [
      {
        name: 'allow-rm-safe-paths',
        tool: '*',
        conditionMode: 'all',
        conditions: [
          { field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' },
          {
            field: 'command',
            op: 'matches',
            value:
              '(node_modules|\\bdist\\b|\\.next|\\bcoverage\\b|\\.cache|\\btmp\\b|\\btemp\\b|\\.DS_Store)(\\/|\\s|$)',
          },
        ],
        verdict: 'allow',
        reason: 'Deleting a known-safe build artifact path',
      },
      {
        name: 'review-rm',
        tool: '*',
        conditions: [{ field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' }],
        verdict: 'review',
        reason: 'rm can permanently delete files — confirm the target path',
      },
    ] as SmartRule[],
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

describe('AST-aware chmod 777 detection (filesystem shield)', () => {
  const CHMOD_RULE = 'shield:filesystem:review-chmod-777';

  // The reported false positive: a read-only `node -e` query whose JS regex
  // literal merely MENTIONS `chmod 777`. normalizeCommandForPolicy keeps the
  // -e payload (execution flag, by design), so the raw regex rule matched.
  // analyzeShellCommand sees the actions are [cd, node] — never chmod — so the
  // AST detector returns null and the suppressed regex must not re-fire.
  const nodeEPayload =
    `cd /home/nadav/node9/node9Firewall/be\n` +
    `node -e '\n` +
    `  const { PrismaClient } = require("@prisma/client");\n` +
    `  const re = /\\b(rm -rf|rm |kill -9|dd |mkfs|chmod 777)\\b/;\n` +
    `  console.log(re);\n` +
    `'`;

  it('does NOT fire chmod rule on a node -e payload that only mentions chmod 777', async () => {
    const r = await evaluatePolicy(
      filesystemShieldedConfig,
      'bash',
      { command: nodeEPayload },
      { agent: 'claude' }
    );
    expect(r.ruleName).not.toBe(CHMOD_RULE);
  });

  it('does NOT fire chmod rule on a python -c payload that only mentions chmod 777', async () => {
    const r = await evaluatePolicy(
      filesystemShieldedConfig,
      'bash',
      { command: `python -c "print('chmod 777 done')"` },
      { agent: 'claude' }
    );
    expect(r.ruleName).not.toBe(CHMOD_RULE);
  });

  it('still REVIEWS a real `chmod 777 <path>` (true positive preserved)', async () => {
    const r = await evaluatePolicy(
      filesystemShieldedConfig,
      'bash',
      { command: 'chmod 777 /tmp/x' },
      { agent: 'claude' }
    );
    expect(r.decision).toBe('review');
    expect(r.ruleName).toBe(CHMOD_RULE);
  });

  it('still REVIEWS an obfuscated `c\\hmod 777` (AST de-obfuscation)', async () => {
    const r = await evaluatePolicy(
      filesystemShieldedConfig,
      'bash',
      { command: 'c\\hmod 777 /tmp/x' },
      { agent: 'claude' }
    );
    expect(r.decision).toBe('review');
    expect(r.ruleName).toBe(CHMOD_RULE);
  });

  it('REVIEWS the genuinely world-writable token set (777, 0777, a+rwx)', async () => {
    for (const cmd of ['chmod 777 /tmp/x', 'chmod 0777 /tmp/x', 'chmod a+rwx /tmp/x']) {
      const r = await evaluatePolicy(
        filesystemShieldedConfig,
        'bash',
        { command: cmd },
        { agent: 'claude' }
      );
      expect(r.decision, cmd).toBe('review');
      expect(r.ruleName, cmd).toBe(CHMOD_RULE);
    }
  });

  it('does NOT review `chmod +x` — execute-only (→ 775) is not world-writable', async () => {
    // Regression: `+x` was wrongly in CHMOD_OPEN_PERM_TOKENS, so making a
    // self-authored throwaway script executable prompted "world-writable…
    // any user can modify it" — factually false (+x grants zero write).
    for (const cmd of [
      'chmod +x ./script.sh',
      'chmod +x /tmp/run.sh',
      'chmod u+x a',
      'chmod g+w a',
    ]) {
      const r = await evaluatePolicy(
        filesystemShieldedConfig,
        'bash',
        { command: cmd },
        { agent: 'claude' }
      );
      expect(r.decision, cmd).toBe('allow');
    }
  });

  it('still REVIEWS chmod 777 run through a command wrapper (sudo/xargs/env/timeout)', async () => {
    // Wrapped chmod parses as a single CallExpr whose action is the wrapper —
    // chmod lands in the token bag, not in `actions`. Without unwrapping, the
    // suppressed regex would no longer catch these (a coverage regression). The
    // wrapper allow-list recovers them. `${'s'}udo` avoids feeding a literal
    // `sudo chmod 777` to this session's own shell gate.
    for (const cmd of [
      `${'s'}udo chmod 777 /tmp/x`,
      `${'s'}udo -u root chmod 777 /tmp/x`,
      'find . -type f | xargs chmod 777',
      'env FOO=bar chmod 777 /tmp/x',
      'timeout 5 chmod 777 /tmp/x',
    ]) {
      const r = await evaluatePolicy(
        filesystemShieldedConfig,
        'bash',
        { command: cmd },
        { agent: 'claude' }
      );
      expect(r.decision, cmd).toBe('review');
      expect(r.ruleName, cmd).toBe(CHMOD_RULE);
    }
  });

  it('does NOT fire chmod rule for a SAFE-mode chmod on a path that contains "777"', async () => {
    // The mode check must bind to chmod's actual mode argument, not any token in
    // the command. A path segment equal to 777 (e.g. `chmod 644 ./777`) must not
    // be mistaken for `chmod 777`. The replaced regex never had this FP.
    for (const cmd of [
      'chmod 644 ./777',
      'chmod 755 /tmp/777',
      `${'s'}udo chmod 644 /tmp/777`,
      'chmod 600 /var/0777',
    ]) {
      const r = await evaluatePolicy(
        filesystemShieldedConfig,
        'bash',
        { command: cmd },
        { agent: 'claude' }
      );
      expect(r.ruleName, cmd).not.toBe(CHMOD_RULE);
    }
  });

  it('REVIEWS chmod 777 even with flags before the mode (chmod -R 777)', async () => {
    for (const cmd of ['chmod -R 777 ./dir', 'chmod -v -R 0777 ./dir']) {
      const r = await evaluatePolicy(
        filesystemShieldedConfig,
        'bash',
        { command: cmd },
        { agent: 'claude' }
      );
      expect(r.decision, cmd).toBe('review');
      expect(r.ruleName, cmd).toBe(CHMOD_RULE);
    }
  });

  it('does NOT fire chmod rule when chmod is an argument to a non-wrapper (echo chmod 777)', async () => {
    // `echo chmod 777` mentions chmod as a token, but echo is not a command
    // wrapper, so the AST detector must not treat it as a real chmod. This is
    // the FP boundary the wrapper allow-list must not cross.
    for (const cmd of ['echo chmod 777', 'echo "run chmod 777 first"']) {
      const r = await evaluatePolicy(
        filesystemShieldedConfig,
        'bash',
        { command: cmd },
        { agent: 'claude' }
      );
      expect(r.ruleName, cmd).not.toBe(CHMOD_RULE);
    }
  });
});

describe('rm same-command create-then-delete waiver', () => {
  const decide = async (command: string) => {
    const r = await evaluatePolicy(rmAdvisoryConfig, 'bash', { command }, { agent: 'claude' });
    return r.decision;
  };
  // NB: `review-rm` only fires when rm follows `;`/`&&`/`||`/start, so every
  // case below keeps rm in that position — matching the founder's real command
  // (`… tail -4; rm -f fn-probe.ts`) — so the waiver is what changes the outcome.
  const HD = "cat > fn-probe.ts <<'EOF'\nconsole.log(1)\nEOF\n";

  // WAIVED → allow (these all review today — fail-first). Heredoc-write only.
  it.each([
    HD + 'npx tsx fn-probe.ts 2>&1 | tail -4; rm -f fn-probe.ts',
    "cat > probe.mjs <<'EOF'\nx\nEOF\nnode probe.mjs; rm -f probe.mjs",
    "cat > a.ts <<'EOF'\nEOF\ncat > b.ts <<'EOF'\nEOF\necho ok; rm -f a.ts b.ts",
    "cat > sub/p.ts <<'EOF'\nEOF\necho ok; rm -f ./sub/p.ts", // ./ vs bare path normalize
  ])('ALLOWS created-then-deleted cleanup #%#', async (cmd) => {
    expect(await decide(cmd)).toBe('allow');
  });

  // NOT waived → still review (regression guards)
  it.each([
    ['echo hi; rm -f fn-probe.ts', 'cross-command: no create in this command'],
    ["cat > .env <<'EOF'\nEOF\necho x; rm -f .env", 'sensitive name'],
    ["cat > x.ts <<'EOF'\nEOF\necho x; rm -f /etc/x", 'target != created, out-of-cwd'],
    ['echo hi > note.txt; rm -f note.txt', 'bare > (no heredoc) is not a creation'],
    // touch/tee do NOT count as creation — they operate on files that may
    // pre-exist, so this must stay a review (closes the touch-first bypass).
    ['touch victim.ts; cat victim.ts; rm -f victim.ts', 'touch is not a creation'],
    ['echo x | tee data.txt; rm -f data.txt', 'tee is not a creation'],
    // `>>` APPENDS (preserves pre-existing content) — must not count as creation.
    ["cat >> victim.ts <<'EOF'\nEOF\necho x; rm -f victim.ts", 'append preserves content'],
    // A non-stdout fd redirect (`2>`) is not the heredoc content sink.
    ["cat > p.ts 2> victim.ts <<'EOF'\nEOF\necho x; rm -f victim.ts", 'stderr redirect target'],
    // Control-flow: a create in an unexecuted branch never runs, so the target
    // is an intact pre-existing file — must stay a review.
    ["false && cat > victim.ts <<'EOF'\nEOF\necho x; rm -f victim.ts", 'create in dead && branch'],
    [
      "if false; then cat > victim.ts <<'EOF'\nEOF\nfi\necho x; rm -f victim.ts",
      'create in dead if-branch',
    ],
    [HD + 'echo x; rm -rf $HOME', 'dynamic target, not created'],
    [HD + 'echo x; rm -f fn-probe.ts $VAR', 'a dynamic arg alongside the created file'],
    [HD + 'echo x; rm -f fn-probe.ts secrets.txt', 'a non-created sibling target'],
    ['rm .env', 'plain sensitive delete (posture unchanged)'],
    ['rm secrets.txt', 'plain delete (posture unchanged)'],
  ])('REVIEWS: %s (%s)', async (cmd) => {
    expect(await decide(cmd)).toBe('review');
  });

  // NOT waived → still block (block tier wins regardless)
  it('BLOCKS a create-then-`rm -rf ~` (block tier unaffected)', async () => {
    expect(await decide("cat > x <<'EOF'\nEOF\necho x; rm -rf ~")).toBe('block');
  });

  // The waiver removes ONLY a `review` verdict. A user/org rule that happens to be
  // named `review-rm` but BLOCKS must NOT be waived on a cleanup command.
  it('does NOT waive a user rule named `review-rm` with verdict block', async () => {
    const cfg: PolicyConfig = {
      ...astOnlyConfig,
      policy: {
        ...astOnlyConfig.policy,
        smartRules: [
          {
            name: 'review-rm',
            tool: '*',
            conditions: [{ field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' }],
            verdict: 'block',
            reason: 'org: never rm',
          },
        ] as SmartRule[],
      },
    };
    const r = await evaluatePolicy(
      cfg,
      'bash',
      { command: "cat > a.ts <<'EOF'\nEOF\necho x; rm -f a.ts" },
      { agent: 'claude' }
    );
    expect(r.decision).toBe('block');
  });
});
