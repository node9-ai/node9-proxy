import { describe, it, expect, vi, beforeEach } from 'vitest';
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
        settings: { mode: 'standard', ...config.settings },
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
    const result = await evaluatePolicy('Shell', { command: 'rm -rf /' });
    expect(result).toBe('review');
  });

  it('identifies "run_shell_command" as a shell-executing tool', async () => {
    mockConfig({});
    const result = await evaluatePolicy('run_shell_command', { command: 'rm -rf /' });
    expect(result).toBe('review');
  });

  it('correctly parses complex shell commands inside run_shell_command', async () => {
    mockConfig({});
    const result = await evaluatePolicy('run_shell_command', { command: 'ls && rm -rf tmp' });
    expect(result).toBe('review');
  });

  it('blocks dangerous commands in Gemini hooks without API key', async () => {
    mockConfig({});
    const result = await authorizeHeadless('Shell', { command: 'rm -rf /' });
    expect(result.approved).toBe(false);
    expect(result.reason).toContain('Node9 blocked "Shell"');
  });

  it('allows safe shell commands in Gemini hooks', async () => {
    mockConfig({});
    const result = await authorizeHeadless('Shell', { command: 'ls -la' });
    expect(result.approved).toBe(true);
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
    expect(dangerousResult).toBe('review');

    const safeResult = await evaluatePolicy('Database.query', {
      payload: { sql: 'SELECT * FROM users;' },
    });
    expect(safeResult).toBe('allow');
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
