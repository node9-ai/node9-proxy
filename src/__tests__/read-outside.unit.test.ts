import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  _resetProjectRootMemo,
  findProjectRoot,
  projectRootOf,
  readOutsidePath,
} from '../audit/read-outside';

// The test setup points HOME at an empty temp folder (helpers/isolate-home).
describe('projectRootOf', () => {
  let dirs: string[] = [];
  beforeEach(() => {
    dirs = [];
  });
  afterEach(() => {
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });

  it('never takes the home folder as the project, even when it holds .git', () => {
    const home = os.homedir();
    fs.mkdirSync(path.join(home, '.git'), { recursive: true });
    dirs.push(path.join(home, '.git'));
    const cwd = path.join(home, 'proj');
    fs.mkdirSync(cwd, { recursive: true });
    dirs.push(cwd);
    expect(projectRootOf(cwd)).toBe(cwd);
  });

  it('climbs to the nearest folder that holds .git', () => {
    const repo = fs.mkdtempSync(path.join(os.homedir(), 'repo-'));
    dirs.push(repo);
    fs.mkdirSync(path.join(repo, '.git'));
    fs.mkdirSync(path.join(repo, 'a', 'b'), { recursive: true });
    expect(projectRootOf(path.join(repo, 'a', 'b'))).toBe(repo);
  });
});

describe('readOutsidePath', () => {
  // A cwd outside temp folders, so the inside/outside rule is what decides.
  const cwd = path.resolve(__dirname, '..', 'audit');

  it('takes the viewed file of the edit tool, not its edits', () => {
    const outside = path.resolve(__dirname, '..', '..', '..', 'elsewhere', 'notes.md');
    expect(
      readOutsidePath('str_replace_based_edit_tool', { command: 'view', path: outside }, cwd)
    ).toBe('elsewhere/notes.md');
    expect(
      readOutsidePath('str_replace_based_edit_tool', { command: 'create', path: outside }, cwd)
    ).toBeUndefined();
  });

  it('ignores a non-read tool and a missing or relative cwd', () => {
    const outside = path.resolve(__dirname, '..', '..', '..', 'elsewhere', 'notes.md');
    expect(readOutsidePath('Write', { file_path: outside }, cwd)).toBeUndefined();
    expect(readOutsidePath('Read', { file_path: outside }, undefined)).toBeUndefined();
    expect(readOutsidePath('Read', { file_path: outside }, 'rel')).toBeUndefined();
  });

  it('reads the absolute_path argument of an older read_file', () => {
    const outside = path.resolve(__dirname, '..', '..', '..', 'elsewhere', 'notes.md');
    expect(readOutsidePath('Read', { absolute_path: outside }, cwd)).toBe('elsewhere/notes.md');
  });

  it('a file inside whose name starts with two dots is inside', () => {
    expect(readOutsidePath('Read', { file_path: path.join(cwd, '..env.local') }, cwd)).toBe(
      undefined
    );
  });
});

describe('findProjectRoot memo', () => {
  it('looks again after a minute, so a new repository shows up', () => {
    const dir = fs.mkdtempSync(path.join(os.homedir(), 'memo-'));
    try {
      _resetProjectRootMemo();
      const now = Date.now();
      const spy = vi.spyOn(Date, 'now').mockReturnValue(now);
      expect(findProjectRoot(dir)).toBeNull();
      fs.mkdirSync(path.join(dir, '.git'));
      // Inside the minute: the memo answers.
      spy.mockReturnValue(now + 30_000);
      expect(findProjectRoot(dir)).toBeNull();
      spy.mockReturnValue(now + 61_000);
      expect(findProjectRoot(dir)).toBe(dir);
      spy.mockRestore();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
