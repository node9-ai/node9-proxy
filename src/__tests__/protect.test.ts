import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { protect } from '../index.js';
import { _resetConfigCache } from '../core.js';

// Fully block all HITL channels — tests use deterministic mechanisms only
vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));
vi.mock('../ui/native', () => ({
  askNativePopup: vi.fn().mockReturnValue('deny'),
  sendDesktopNotification: vi.fn(),
}));

const existsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
const readSpy = vi.spyOn(fs, 'readFileSync').mockReturnValue('');
vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');

beforeEach(() => {
  _resetConfigCache();
  delete process.env.NODE9_API_KEY;
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
});

/** Grant approval for a tool via a persistent decision file (no HITL needed). */
function setPersistentDecision(toolName: string, decision: 'allow' | 'deny') {
  const decisionsPath = path.join(os.homedir(), '.node9', 'decisions.json');
  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  existsSpy.mockImplementation((p) => String(p) === decisionsPath || String(p) === globalPath);
  readSpy.mockImplementation((p) => {
    if (String(p) === decisionsPath) return JSON.stringify({ [toolName]: decision });
    if (String(p) === globalPath)
      return JSON.stringify({ settings: { mode: 'standard', approvalTimeoutMs: 0 } });
    return '';
  });
}

describe('protect()', () => {
  it('calls the wrapped function and returns its result when approved', async () => {
    // Changed 'delete_resource' -> 'drop_resource'
    setPersistentDecision('drop_resource', 'allow');

    const fn = vi.fn().mockResolvedValue('ok');
    const secured = protect('drop_resource', fn);

    const result = await secured('arg1', 42);

    expect(fn).toHaveBeenCalledWith('arg1', 42);
    expect(result).toBe('ok');
  });

  it('throws and does NOT call the wrapped function when denied', async () => {
    // 'mkfs_resource' contains 'mkfs' (in DANGEROUS_WORDS) so it evaluates to review,
    // then the persistent deny decision kicks in.
    setPersistentDecision('mkfs_resource', 'deny');

    const fn = vi.fn();
    const secured = protect('mkfs_resource', fn);

    await expect(secured()).rejects.toThrow(/denied/i);
    expect(fn).not.toHaveBeenCalled();
  });

  it('does not prompt for safe tools and calls the function directly', async () => {
    const { confirm } = await import('@inquirer/prompts');

    const fn = vi.fn().mockResolvedValue('data');
    const secured = protect('list_users', fn);

    const result = await secured();

    // Ignored tool — fast-path allow with no approval channel touched
    expect(confirm).not.toHaveBeenCalled();
    expect(fn).toHaveBeenCalledTimes(1);
    expect(result).toBe('data');
  });

  it('preserves the original function return type', async () => {
    setPersistentDecision('delete_record', 'allow');

    const fn = vi.fn().mockResolvedValue({ id: 1, name: 'test' });
    const secured = protect('delete_record', fn);

    const result = await secured();
    expect(result).toEqual({ id: 1, name: 'test' });
  });
});
