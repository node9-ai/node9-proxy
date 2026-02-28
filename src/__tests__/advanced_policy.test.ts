import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { evaluatePolicy, _resetConfigCache } from '../core';
import fs from 'fs';
import os from 'os';
import path from 'path';

describe('Path-Based Policy (Advanced)', () => {
  const configPath = path.join(process.cwd(), 'node9.config.json');

  beforeEach(() => {
    vi.mock('fs', async () => {
      const actual = await vi.importActual<typeof import('fs')>('fs');
      return {
        ...actual,
        existsSync: vi.fn(),
        readFileSync: vi.fn(),
      };
    });
    _resetConfigCache();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('allows "rm -rf node_modules" with recursive glob pattern', () => {
    const mockConfig = {
      policy: {
        dangerousWords: ['rm'],
        rules: [{ action: 'rm', allowPaths: ['**/node_modules/**'] }]
      }
    };
    vi.spyOn(fs, 'existsSync').mockImplementation((p) => p === configPath);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockConfig));

    expect(evaluatePolicy('Bash', { command: 'rm -rf node_modules' })).toBe('allow');
    expect(evaluatePolicy('Bash', { command: 'rm -rf ./subdir/node_modules' })).toBe('allow');
  });

  it('blocks "rm -rf src" when not in allow list', () => {
    const mockConfig = {
      policy: {
        dangerousWords: ['rm'],
        rules: [{ action: 'rm', allowPaths: ['**/node_modules/**'] }]
      }
    };
    vi.spyOn(fs, 'existsSync').mockImplementation((p) => p === configPath);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockConfig));

    expect(evaluatePolicy('Bash', { command: 'rm -rf src' })).toBe('review');
  });

  it('blocks "rm -rf .env" using explicit blockPaths', () => {
    const mockConfig = {
      policy: {
        dangerousWords: ['rm'],
        rules: [{ action: 'rm', allowPaths: ['tmp/**'], blockPaths: ['.env'] }]
      }
    };
    vi.spyOn(fs, 'existsSync').mockImplementation((p) => p === configPath);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockConfig));

    expect(evaluatePolicy('Bash', { command: 'rm .env' })).toBe('review');
  });

  it('correctly tokenizes and identifies "rm" even with complex shell syntax', () => {
    const mockConfig = {
      policy: {
        dangerousWords: ['rm'],
        rules: [{ action: 'rm', allowPaths: ['**/tmp/**'] }]
      }
    };
    vi.spyOn(fs, 'existsSync').mockImplementation((p) => p === configPath);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockConfig));

    // Pipe bypass attempt
    expect(evaluatePolicy('Bash', { command: 'echo "hello" | rm' })).toBe('review');
    // Escaped bypass attempt
    expect(evaluatePolicy('Bash', { command: 'r\m -rf /' })).toBe('review');
  });
});
