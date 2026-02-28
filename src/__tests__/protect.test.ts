import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import { protect } from '../index.js';
import { _resetConfigCache } from '../core.js';

vi.mock('@inquirer/prompts', () => ({
  confirm: vi.fn(),
}));

vi.spyOn(fs, 'existsSync').mockReturnValue(false);
vi.spyOn(fs, 'readFileSync');

beforeEach(() => {
  _resetConfigCache();
  delete process.env.NODE9_API_KEY;
  Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
});

describe('protect()', () => {
  it('calls the wrapped function and returns its result when approved', async () => {
    const { confirm } = await import('@inquirer/prompts');
    vi.mocked(confirm).mockResolvedValue(true);

    const fn = vi.fn().mockResolvedValue('ok');
    const secured = protect('delete_resource', fn);

    const result = await secured('arg1', 42);

    expect(fn).toHaveBeenCalledWith('arg1', 42);
    expect(result).toBe('ok');
  });

  it('throws and does NOT call the wrapped function when denied', async () => {
    const { confirm } = await import('@inquirer/prompts');
    vi.mocked(confirm).mockResolvedValue(false);

    const fn = vi.fn();
    const secured = protect('delete_resource', fn);

    await expect(secured()).rejects.toThrow(/denied/i);
    expect(fn).not.toHaveBeenCalled();
  });

  it('does not prompt for safe tools and calls the function directly', async () => {
    const { confirm } = await import('@inquirer/prompts');

    const fn = vi.fn().mockResolvedValue('data');
    const secured = protect('list_users', fn);

    const result = await secured();

    expect(confirm).not.toHaveBeenCalled();
    expect(fn).toHaveBeenCalledTimes(1);
    expect(result).toBe('data');
  });

  it('preserves the original function return type', async () => {
    const { confirm } = await import('@inquirer/prompts');
    vi.mocked(confirm).mockResolvedValue(true);

    const fn = vi.fn().mockResolvedValue({ id: 1, name: 'test' });
    const secured = protect('delete_record', fn);

    const result = await secured();
    expect(result).toEqual({ id: 1, name: 'test' });
  });
});
