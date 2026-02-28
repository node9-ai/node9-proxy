import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { authorizeAction, evaluatePolicy, authorizeHeadless, _resetConfigCache } from '../core.js';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));

// Global spies
const existsSpy = vi.spyOn(fs, 'existsSync');
const readSpy = vi.spyOn(fs, 'readFileSync');
const writeSpy = vi.spyOn(fs, 'writeFileSync');
const mkdirSpy = vi.spyOn(fs, 'mkdirSync');
const homeSpy = vi.spyOn(os, 'homedir');

async function getConfirm() {
  return vi.mocked((await import('@inquirer/prompts')).confirm);
}

beforeEach(() => {
  _resetConfigCache();
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  writeSpy.mockImplementation(() => undefined);
  mkdirSpy.mockImplementation(() => undefined);
  homeSpy.mockReturnValue('/mock/home');

  // Default headless
  Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('authorizeAction', () => {
  it('returns true for safe tool calls', async () => {
    const confirm = await getConfirm();
    expect(await authorizeAction('list_users', {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('prompts user for dangerous actions when no API key is configured', async () => {
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

    expect(await authorizeAction('delete_user', { id: 123 })).toBe(true);
    expect(confirm).toHaveBeenCalled();
  });

  it('returns false when user denies terminal approval', async () => {
    const confirm = await getConfirm();
    confirm.mockResolvedValue(false);
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

    expect(await authorizeAction('drop_table', { name: 'users' })).toBe(false);
  });
});

describe('evaluatePolicy', () => {
  it.each(['list_users', 'get_config', 'read_file', 'describe_table'])(
    'returns "allow" for ignored tool "%s"',
    async (tool) => {
      expect(await evaluatePolicy(tool)).toBe('allow');
    }
  );

  it.each(['delete_user', 'drop_table', 'rm_data', 'destroy_cluster'])(
    'returns "review" for dangerous tool "%s"',
    async (tool) => {
      expect(await evaluatePolicy(tool)).toBe('review');
    }
  );

  it('respects project-level node9.config.json', async () => {
    const projectPath = path.join(process.cwd(), 'node9.config.json');
    existsSpy.mockImplementation((p) => String(p) === projectPath);
    readSpy.mockImplementation((p) => {
      if (String(p) === projectPath) {
        return JSON.stringify({ policy: { dangerousWords: ['deploy'] } });
      }
      return '';
    });

    expect(await evaluatePolicy('deploy_app')).toBe('review');
    expect(await evaluatePolicy('delete_user')).toBe('allow');
  });
});

describe('authorizeHeadless', () => {
  it('returns approved:true for safe actions', async () => {
    const result = await authorizeHeadless('list_users', {});
    expect(result).toEqual({ approved: true });
  });

  it('returns approved:false with a helpful reason when no API key is configured', async () => {
    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(false);
    expect(result.reason).toMatch(/node9 login/i);
  });
});
