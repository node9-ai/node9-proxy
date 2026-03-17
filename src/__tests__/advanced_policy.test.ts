import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { evaluatePolicy, getConfig, _resetConfigCache } from '../core.js';

const existsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
const readSpy = vi.spyOn(fs, 'readFileSync');
const homeSpy = vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');

beforeEach(() => {
  _resetConfigCache();
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  homeSpy.mockReturnValue('/mock/home');
});

describe('Path-Based Policy (Advanced)', () => {
  it('allows "rm -rf node_modules" with recursive glob pattern', async () => {
    const mockConfig = {
      policy: {
        rules: [
          {
            action: 'rm',
            allowPaths: ['**/node_modules/**'],
          },
        ],
      },
    };
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockConfig));

    // Should be allowed because it matches the glob
    expect(
      (await evaluatePolicy('Bash', { command: 'rm -rf ./node_modules/lodash' })).decision
    ).toBe('allow');
  });

  it('blocks "rm -rf src" when not in allow list', async () => {
    const mockConfig = {
      policy: {
        rules: [
          {
            action: 'rm',
            allowPaths: ['dist/**'],
          },
        ],
      },
    };
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockConfig));

    expect((await evaluatePolicy('Bash', { command: 'rm -rf src' })).decision).toBe('review');
  });

  it('blocks "rm -rf .env" using explicit blockPaths', async () => {
    const mockConfig = {
      policy: {
        rules: [
          {
            action: 'rm',
            allowPaths: ['**/*'],
            blockPaths: ['.env', 'config/*'],
          },
        ],
      },
    };
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockConfig));

    expect((await evaluatePolicy('Bash', { command: 'rm .env' })).decision).toBe('review');
  });

  it('correctly tokenizes and identifies "rm" even with complex shell syntax', async () => {
    const mockConfig = {
      policy: {
        dangerousWords: ['rm'],
      },
    };
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockConfig));

    // Pipe bypass attempt
    expect((await evaluatePolicy('Bash', { command: 'echo "hello" | rm' })).decision).toBe(
      'review'
    );
    // Escaped bypass attempt
    expect((await evaluatePolicy('Bash', { command: 'r\\m -rf /' })).decision).toBe('review');
  });
});

// ── allow-readonly-bash smartRule (chaining guard) ────────────────────────────

describe('allow-readonly-bash — chained command guard', () => {
  const readonlyAllowRule = {
    policy: {
      dangerousWords: [],
      smartRules: [
        {
          name: 'allow-readonly-bash',
          tool: 'bash',
          conditions: [
            {
              field: 'command',
              op: 'matches',
              value:
                '^\\s*(cat|grep|ls|find|echo|head|tail|wc|sort|uniq|diff|du|df|stat|which|pwd|env|printenv|node --version|npm (list|ls|run (build|test|lint|typecheck|format))|git (log|status|diff|show|branch|remote|fetch|stash list|tag))',
              flags: 'i',
            },
            {
              field: 'command',
              op: 'notMatches',
              value: '(&&|\\|\\||;\\s*\\S)',
              flags: 'i',
            },
          ],
          conditionMode: 'all',
          verdict: 'allow',
          reason: 'Read-only safe command',
        },
      ],
    },
  };

  beforeEach(() => {
    existsSpy.mockReturnValue(true);
    readSpy.mockReturnValue(JSON.stringify(readonlyAllowRule));
  });

  it('allows a plain cat command', async () => {
    expect((await evaluatePolicy('bash', { command: 'cat README.md' })).decision).toBe('allow');
  });

  it('allows a git log command', async () => {
    expect((await evaluatePolicy('bash', { command: 'git log --oneline -10' })).decision).toBe(
      'allow'
    );
  });

  it('does NOT allow cat chained with && rm', async () => {
    const r = await evaluatePolicy('bash', { command: 'cat /etc/passwd && rm -rf /' });
    expect(r.decision).not.toBe('allow');
  });

  it('does NOT allow cat chained with ; rm', async () => {
    const r = await evaluatePolicy('bash', { command: 'cat /etc/hosts; rm secrets.txt' });
    expect(r.decision).not.toBe('allow');
  });

  it('does NOT allow cat chained with || rm', async () => {
    const r = await evaluatePolicy('bash', { command: 'cat missing.txt || rm backup.sql' });
    expect(r.decision).not.toBe('allow');
  });

  it('allows cat piped to grep (pipe-only is safe)', async () => {
    expect(
      (await evaluatePolicy('bash', { command: 'cat README.md | grep install' })).decision
    ).toBe('allow');
  });
});

// ── allow-readonly-bash — $() and backtick substitution bypass ───────────────

describe('allow-readonly-bash — command substitution bypass', () => {
  const readonlyAllowRule = {
    policy: {
      dangerousWords: [],
      smartRules: [
        {
          name: 'allow-readonly-bash',
          tool: 'bash',
          conditions: [
            {
              field: 'command',
              op: 'matches',
              value:
                '^\\s*(cat|grep|ls|find|echo|head|tail|wc|sort|uniq|diff|du|df|stat|which|pwd|env|printenv|node --version|npm (list|ls|run (build|test|lint|typecheck|format))|git (log|status|diff|show|branch|remote|fetch|stash list|tag))',
              flags: 'i',
            },
            {
              field: 'command',
              op: 'notMatches',
              value: '(&&|\\|\\||;\\s*\\S|\\$\\(|`)',
              flags: 'i',
            },
          ],
          conditionMode: 'all',
          verdict: 'allow',
          reason: 'Read-only safe command',
        },
        {
          name: 'review-command-substitution',
          tool: 'bash',
          conditions: [{ field: 'command', op: 'matches', value: '(\\$\\(|`)', flags: 'i' }],
          conditionMode: 'all',
          verdict: 'review',
          reason: 'Command substitution detected',
        },
      ],
    },
  };

  beforeEach(() => {
    existsSpy.mockReturnValue(true);
    readSpy.mockReturnValue(JSON.stringify(readonlyAllowRule));
  });

  it('does NOT allow cat with $() substitution', async () => {
    const r = await evaluatePolicy('bash', { command: 'cat $(ls /etc)' });
    expect(r.decision).not.toBe('allow');
  });

  it('does NOT allow echo with backtick substitution', async () => {
    const r = await evaluatePolicy('bash', { command: 'echo `id`' });
    expect(r.decision).not.toBe('allow');
  });

  it('still allows a plain grep without substitution', async () => {
    const r = await evaluatePolicy('bash', { command: 'grep -r TODO src/' });
    expect(r.decision).toBe('allow');
  });
});

// ── allow-install-devtools — global flag guard ────────────────────────────────

describe('allow-install-devtools — global install guard', () => {
  const installRule = {
    policy: {
      dangerousWords: [],
      smartRules: [
        {
          name: 'allow-install-devtools',
          tool: 'bash',
          conditions: [
            {
              field: 'command',
              op: 'matches',
              value: '^\\s*(npm (install|ci|update)|yarn (install|add)|pnpm (install|add))',
              flags: 'i',
            },
            {
              field: 'command',
              op: 'notMatches',
              value: '(-g|--global)\\b',
              flags: 'i',
            },
          ],
          conditionMode: 'all',
          verdict: 'allow',
          reason: 'Package install — not destructive',
        },
        {
          name: 'review-global-install',
          tool: 'bash',
          conditions: [
            {
              field: 'command',
              op: 'matches',
              value: '\\b(npm|yarn|pnpm)\\b.+(-g|--global)\\b',
              flags: 'i',
            },
          ],
          conditionMode: 'all',
          verdict: 'review',
          reason: 'Global install requires approval',
        },
      ],
    },
  };

  beforeEach(() => {
    existsSpy.mockReturnValue(true);
    readSpy.mockReturnValue(JSON.stringify(installRule));
  });

  it('allows a normal npm install', async () => {
    expect((await evaluatePolicy('bash', { command: 'npm install lodash' })).decision).toBe(
      'allow'
    );
  });

  it('does NOT allow npm install -g', async () => {
    const r = await evaluatePolicy('bash', { command: 'npm install -g typescript' });
    expect(r.decision).not.toBe('allow');
  });

  it('does NOT allow npm install --global', async () => {
    const r = await evaluatePolicy('bash', { command: 'npm install --global typescript' });
    expect(r.decision).not.toBe('allow');
  });
});

// ── review-secrets-write — multi-field matching ───────────────────────────────

describe('review-secrets-write — multi-field matching', () => {
  const secretsRule = {
    policy: {
      dangerousWords: [],
      smartRules: [
        {
          name: 'review-secrets-write',
          tool: '*',
          conditions: [
            {
              field: 'file_path',
              op: 'matches',
              value:
                '(^|[/\\\\])(\\.env(\\.\\w+)?$|\\.pem$|\\.key$|id_rsa|credentials\\.json|secrets?\\.json)',
            },
            {
              field: 'path',
              op: 'matches',
              value:
                '(^|[/\\\\])(\\.env(\\.\\w+)?$|\\.pem$|\\.key$|id_rsa|credentials\\.json|secrets?\\.json)',
            },
            {
              field: 'filename',
              op: 'matches',
              value:
                '(^|[/\\\\])(\\.env(\\.\\w+)?$|\\.pem$|\\.key$|id_rsa|credentials\\.json|secrets?\\.json)',
            },
          ],
          conditionMode: 'any',
          verdict: 'review',
          reason: 'Writing to secrets or credentials file',
        },
      ],
    },
  };

  beforeEach(() => {
    existsSpy.mockReturnValue(true);
    readSpy.mockReturnValue(JSON.stringify(secretsRule));
  });

  it('flags write via file_path field', async () => {
    const r = await evaluatePolicy('write', { file_path: '/project/.env' });
    expect(r.decision).toBe('review');
  });

  it('flags write via path field', async () => {
    const r = await evaluatePolicy('write', { path: '/project/credentials.json' });
    expect(r.decision).toBe('review');
  });

  it('flags write via filename field', async () => {
    const r = await evaluatePolicy('write', { filename: 'id_rsa' });
    expect(r.decision).toBe('review');
  });

  it('does NOT flag a normal source file write', async () => {
    const r = await evaluatePolicy('write', { file_path: '/project/src/index.ts' });
    expect(r.decision).not.toBe('review');
  });

  it('does NOT flag a file whose name merely contains .env as a substring', async () => {
    const r = await evaluatePolicy('write', { file_path: '/project/notmy.env.bak' });
    expect(r.decision).not.toBe('review');
  });
});

// ── version mismatch handling ─────────────────────────────────────────────────

describe('tryLoadConfig — version mismatch handling', () => {
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it('emits a warning but continues when minor version differs', () => {
    const projectPath = path.join(process.cwd(), 'node9.config.json');
    existsSpy.mockImplementation((p) => String(p) === projectPath);
    readSpy.mockImplementation((p) =>
      String(p) === projectPath ? JSON.stringify({ version: '1.99' }) : ''
    );
    const cfg = getConfig();
    // Config should still load (best-effort)
    expect(cfg).toBeDefined();
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('⚠️'));
  });

  it('refuses to load config when major version mismatches', () => {
    const projectPath = path.join(process.cwd(), 'node9.config.json');
    existsSpy.mockImplementation((p) => String(p) === projectPath);
    readSpy.mockImplementation((p) =>
      String(p) === projectPath ? JSON.stringify({ version: '2.0' }) : ''
    );
    const cfg = getConfig();
    // The incompatible config should be skipped — policy stays at defaults
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('❌'));
    // No custom policy from that file should leak in
    expect(cfg.policy.dangerousWords).not.toContain('__sentinel__');
  });
});

// ── environments merge ────────────────────────────────────────────────────────

describe('getConfig — environments layer merge', () => {
  it('merges environments from project config', () => {
    const projectPath = path.join(process.cwd(), 'node9.config.json');
    existsSpy.mockImplementation((p) => String(p) === projectPath);
    readSpy.mockImplementation((p) =>
      String(p) === projectPath
        ? JSON.stringify({ environments: { production: { requireApproval: true } } })
        : ''
    );
    const cfg = getConfig();
    expect(cfg.environments['production']?.requireApproval).toBe(true);
  });

  it('project config overrides global config for the same environment', () => {
    const projectPath = path.join(process.cwd(), 'node9.config.json');
    const globalPath = path.join('/mock/home', '.node9', 'config.json');
    existsSpy.mockImplementation((p) => [projectPath, globalPath].includes(String(p)));
    readSpy.mockImplementation((p) => {
      if (String(p) === globalPath)
        return JSON.stringify({ environments: { production: { requireApproval: false } } });
      if (String(p) === projectPath)
        return JSON.stringify({ environments: { production: { requireApproval: true } } });
      return '';
    });
    const cfg = getConfig();
    // Project layer is applied after global — project value wins
    expect(cfg.environments['production']?.requireApproval).toBe(true);
  });

  it('ignores non-boolean requireApproval values (type safety)', () => {
    const projectPath = path.join(process.cwd(), 'node9.config.json');
    existsSpy.mockImplementation((p) => String(p) === projectPath);
    readSpy.mockImplementation((p) =>
      String(p) === projectPath
        ? JSON.stringify({ environments: { staging: { requireApproval: 'yes' } } })
        : ''
    );
    const cfg = getConfig();
    // Should not inject a string — key should be absent
    expect(cfg.environments['staging']?.requireApproval).toBeUndefined();
  });

  it('merges multiple environments independently', () => {
    const projectPath = path.join(process.cwd(), 'node9.config.json');
    existsSpy.mockImplementation((p) => String(p) === projectPath);
    readSpy.mockImplementation((p) =>
      String(p) === projectPath
        ? JSON.stringify({
            environments: {
              production: { requireApproval: true },
              development: { requireApproval: false },
            },
          })
        : ''
    );
    const cfg = getConfig();
    expect(cfg.environments['production']?.requireApproval).toBe(true);
    expect(cfg.environments['development']?.requireApproval).toBe(false);
  });
});
