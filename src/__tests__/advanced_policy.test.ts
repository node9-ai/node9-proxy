import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import { evaluatePolicy, _resetConfigCache } from '../core.js';

vi.spyOn(fs, 'existsSync').mockReturnValue(false);
vi.spyOn(fs, 'readFileSync');

beforeEach(() => {
  _resetConfigCache();
  vi.mocked(fs.existsSync).mockReturnValue(false);
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
    expect(await evaluatePolicy('Bash', { command: 'rm -rf ./node_modules/lodash' })).toBe('allow');
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

    expect(await evaluatePolicy('Bash', { command: 'rm -rf src' })).toBe('review');
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

    expect(await evaluatePolicy('Bash', { command: 'rm .env' })).toBe('review');
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
    expect(await evaluatePolicy('Bash', { command: 'echo "hello" | rm' })).toBe('review');
    // Escaped bypass attempt
    expect(await evaluatePolicy('Bash', { command: 'r\\m -rf /' })).toBe('review');
  });
});
