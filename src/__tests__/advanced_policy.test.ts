import { describe, it, expect, vi, beforeEach } from 'vitest';
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
