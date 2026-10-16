import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { evaluateProtectedFileAccess } from '@node9/policy-engine';
import { prepareFileAccesses } from '../policy/file-access';

// The protected-file policy is POSIX-only: on win32 the host prepares no
// accesses and legacy path DLP keeps its block (see src/policy/file-access.ts).
describe.skipIf(process.platform === 'win32')('protected file host resolution', () => {
  let dir: string;
  let home: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-protected-'));
    home = path.join(dir, 'home');
    fs.mkdirSync(home);
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
  function judge(tool: string, args: unknown, cwd = dir) {
    const prepared = prepareFileAccesses(tool, args, cwd, {}, home);
    return { prepared, result: evaluateProtectedFileAccess(prepared.accesses, prepared, {}) };
  }
  it('finds a missing startup file through its symlinked parent', () => {
    fs.symlinkSync(home, path.join(dir, 'alias'));
    expect(judge('Write', { file_path: 'alias/.bashrc' }).result?.decision).toBe('review');
  });
  it('follows a dangling link when a write would create its target', () => {
    fs.symlinkSync(path.join(home, '.bashrc'), path.join(dir, 'link'));
    expect(judge('Write', { path: 'link' }).result?.decision).toBe('review');
    expect(judge('Bash', { command: 'rm link' }).result).toBeNull();
  });
  it('resolves literal symlink prefixes before matching shell patterns', () => {
    fs.symlinkSync(home, path.join(dir, 'alias'));
    expect(judge('Bash', { command: 'rm alias/.*rc' }).result?.decision).toBe('review');
  });
  it('finds a protected startup file relocated into a dotfiles checkout', () => {
    const target = path.join(dir, 'shellrc');
    fs.writeFileSync(target, 'fixture');
    fs.symlinkSync(target, path.join(home, '.bashrc'));
    expect(judge('Write', { file_path: target }).result?.decision).toBe('review');
  });
  it('detects recursive removal of a relocated startup target', () => {
    const checkout = path.join(dir, 'dotfiles');
    fs.mkdirSync(checkout);
    const target = path.join(checkout, 'shellrc');
    fs.writeFileSync(target, 'fixture');
    fs.symlinkSync(target, path.join(home, '.bashrc'));
    expect(judge('Bash', { command: `rm -rf ${checkout}` }).result?.decision).toBe('review');
  });
  it('distinguishes unlinking a symlink from writing through it', () => {
    const startup = path.join(home, '.bashrc');
    fs.writeFileSync(startup, 'fixture');
    fs.symlinkSync(startup, path.join(dir, 'link'));
    expect(judge('Bash', { command: 'rm link' }).result).toBeNull();
    expect(judge('Bash', { command: 'echo x > link' }).result?.decision).toBe('review');
    expect(judge('Bash', { command: `rm ${startup}` }).result?.decision).toBe('review');
  });
  it('resolves symlinks before the following parent traversal', () => {
    fs.mkdirSync(path.join(home, 'child'));
    fs.symlinkSync(path.join(home, 'child'), path.join(dir, 'link'));
    expect(judge('Write', { path: 'link/../.bashrc' }).result?.decision).toBe('review');
  });
  it('resolves copy destination directories and honors target-file flags', () => {
    expect(judge('Bash', { command: `cp /tmp/.bashrc ${home}` }).result?.decision).toBe('review');
    expect(judge('Bash', { command: `cp -T /tmp/.bashrc ${home}` }).result).toBeNull();
    const file = path.join(dir, 'ordinary');
    fs.writeFileSync(file, 'fixture');
    expect(judge('Bash', { command: `cp /tmp/.bashrc ${file}` }).result).toBeNull();
  });
  it('does not reuse physical resolution after a symlink changes', () => {
    const link = path.join(dir, 'link');
    fs.symlinkSync(home, link);
    expect(judge('Write', { path: 'link/.bashrc' }).result?.decision).toBe('review');
    fs.unlinkSync(link);
    fs.mkdirSync(link);
    expect(judge('Write', { path: 'link/.bashrc' }).result).toBeNull();
  });
  it('checks relative file-tool paths using the supplied cwd', () => {
    expect(judge('Edit', { path: '.bashrc' }, home).result?.decision).toBe('review');
    expect(judge('Edit', { path: '.bashrc' }, dir).result).toBeNull();
  });
  it('does not turn a timestamp update into a content write', () => {
    fs.writeFileSync(path.join(home, '.bashrc'), 'fixture');
    expect(judge('Bash', { command: 'touch ~/.bashrc' }).result).toBeNull();
    expect(judge('Bash', { command: 'touch ~/.zshrc' }).result?.decision).toBe('review');
  });
  it('does not hand unknown tool paths over from legacy DLP', () => {
    expect(judge('plugin_lookup', { path: '/etc/shadow' }).prepared.handledPaths.size).toBe(0);
    expect(judge('Read', { path: '/etc/shadow' }).prepared.handledPaths.has('/etc/shadow')).toBe(
      true
    );
  });
});
