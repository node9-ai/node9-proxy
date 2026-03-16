// 1. MUST be the very first lines of the file
import { vi } from 'vitest';

// 2. Add '.js' to the path and use 'mockResolvedValue' (since it's an async function now)
vi.mock('../ui/native.js', () => ({
  askNativePopup: vi.fn().mockResolvedValue('deny'),
  sendDesktopNotification: vi.fn(),
}));

// 3. Now perform your regular imports
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import { evaluatePolicy, authorizeHeadless, _resetConfigCache, DANGEROUS_WORDS } from '../core.js';
import { setupGemini } from '../setup.js';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));

const existsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
const readSpy = vi.spyOn(fs, 'readFileSync');
vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');

interface MockConfig {
  settings?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  environments?: Record<string, unknown>;
}

function mockConfig(config: MockConfig) {
  const globalPath = '/mock/home/.node9/config.json';
  existsSpy.mockImplementation((p) => String(p) === globalPath);
  readSpy.mockImplementation((p) => {
    if (String(p) === globalPath) {
      return JSON.stringify({
        settings: { mode: 'standard', approvers: { native: false }, ...config.settings },
        policy: {
          dangerousWords: DANGEROUS_WORDS, // Use defaults!
          ignoredTools: [],
          toolInspection: {
            Shell: 'command',
            run_shell_command: 'command',
            bash: 'command',
          },
          rules: [],
          ...config.policy,
        },
        environments: config.environments || {},
      });
    }
    return '';
  });
}

beforeEach(() => {
  _resetConfigCache();
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
});

describe('Gemini Integration Security', () => {
  it('identifies "Shell" (capital S) as a shell-executing tool', async () => {
    mockConfig({});
    // mkfs is in DANGEROUS_WORDS — proves Shell is inspected as a shell tool
    const result = await evaluatePolicy('Shell', { command: 'mkfs.ext4 /dev/sdb' });
    expect(result.decision).toBe('review');
  });

  it('identifies "run_shell_command" as a shell-executing tool', async () => {
    mockConfig({});
    // mkfs is in DANGEROUS_WORDS — catches filesystem-wiping commands
    const result = await evaluatePolicy('run_shell_command', { command: 'mkfs.ext4 /dev/sdb' });
    expect(result.decision).toBe('review');
  });

  it('correctly parses complex shell commands inside run_shell_command', async () => {
    mockConfig({});
    // Proves the AST parser finds the dangerous token even at the end of a chain
    const result = await evaluatePolicy('run_shell_command', {
      command: 'ls -la && mkfs /dev/sdb',
    });
    expect(result.decision).toBe('review');
  });

  it('blocks dangerous commands in Gemini hooks without API key', async () => {
    mockConfig({});
    // mkfs triggers dangerous-word review; no native/cloud approver → noApprovalMechanism
    const result = await authorizeHeadless('Shell', { command: 'mkfs /dev/sda' });
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
  });

  it('allows safe shell commands in Gemini hooks', async () => {
    mockConfig({});
    const result = await authorizeHeadless('Shell', { command: 'ls -la' });
    expect(result.approved).toBe(true);
  });

  // FIXED TEST: Use a path that is in the DEFAULT_CONFIG allowPaths list (like 'dist')
  it('allows "rm" on specific allowed paths even if the verb is monitored', async () => {
    mockConfig({
      policy: {
        rules: [{ action: 'rm', allowPaths: ['dist/**'] }],
      },
    });
    const result = await evaluatePolicy('run_shell_command', { command: 'rm -rf dist/old_build' });
    expect(result.decision).toBe('allow');
  });

  it('Universal Adapter: dynamically inspects a custom tool defined in config', async () => {
    mockConfig({
      policy: {
        dangerousWords: ['DROP', 'DELETE'],
        toolInspection: {
          'Database.*': 'payload.sql',
        },
      },
    });

    const dangerousResult = await evaluatePolicy('Database.query', {
      payload: { sql: 'DROP TABLE users;' },
    });
    expect(dangerousResult.decision).toBe('review');

    const safeResult = await evaluatePolicy('Database.query', {
      payload: { sql: 'SELECT * FROM users;' },
    });
    expect(safeResult.decision).toBe('allow');
  });
});

describe('Gemini BeforeTool payload format', () => {
  it('evaluates tool policy from Gemini { name, args } format', async () => {
    mockConfig({});
    // Gemini sends { name, args } not { tool_name, tool_input }
    const dangerous = await evaluatePolicy('Shell', { command: 'rm -rf /' });
    expect(dangerous.decision).toBe('review');
  });

  it('blocks dangerous Gemini tool via name/args format', async () => {
    mockConfig({});
    const result = await authorizeHeadless('Shell', { command: 'rm -rf /' });
    expect(result.approved).toBe(false);
  });

  it('allows safe Gemini read tool via name/args format', async () => {
    mockConfig({
      policy: { ignoredTools: ['read_*', 'ReadFile'] },
    });
    const result = await authorizeHeadless('ReadFile', { path: '/etc/hosts' });
    expect(result.approved).toBe(true);
  });
});

describe('Gemini Setup (New Schema)', () => {
  const settingsPath = '/mock/home/.gemini/settings.json';

  it('converts old object-based hooks to the new array-based schema', async () => {
    existsSpy.mockImplementation((p) => String(p) === settingsPath);
    readSpy.mockImplementation((p) => {
      if (String(p) === settingsPath) {
        return JSON.stringify({
          hooks: {
            BeforeTool: { command: 'old-way' },
          },
        });
      }
      return '';
    });

    await setupGemini();

    const writes = vi.mocked(fs.writeFileSync).mock.calls;
    const lastWrite = JSON.parse(String(writes[writes.length - 1][1]));
    expect(Array.isArray(lastWrite.hooks.AfterTool)).toBe(true);
    expect(lastWrite.hooks.AfterTool[0].matcher).toBe('.*');
  });
});
