import { afterEach, describe, expect, it } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';

const cli = path.resolve(__dirname, '../../dist/cli.js');
const homes: string[] = [];
function fixture(config?: object) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-first-run-'));
  homes.push(home);
  if (config) {
    fs.mkdirSync(path.join(home, '.node9'));
    fs.writeFileSync(path.join(home, '.node9/config.json'), JSON.stringify(config));
  }
  return home;
}
function run(home: string, args: string[]) {
  // Deliberately do not inherit credentials or agent identity from the host.
  // Agent discovery also searches system-wide install directories. Mask only
  // those executable probes so this fixture models a machine without agents.
  const preload = path.join(home, 'hide-system-agents.cjs');
  fs.writeFileSync(
    preload,
    `const fs = require('fs');
const original = fs.accessSync;
fs.accessSync = function(file, ...args) {
  if (/^\\/(usr\\/local|opt\\/homebrew)\\/bin\\//.test(String(file))) {
    const error = new Error('Fixture: no system agents'); error.code = 'ENOENT'; throw error;
  }
  return original.call(this, file, ...args);
};`
  );
  return spawnSync(process.execPath, ['--require', preload, cli, ...args], {
    cwd: home,
    env: {
      PATH: path.join(home, 'empty-bin'),
      HOME: home,
      USERPROFILE: home,
      CI: 'true',
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
    },
    encoding: 'utf8',
    timeout: 10000,
  });
}
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});
describe('setup CLI without a terminal', () => {
  it('bare invocation only shows help and never writes config', () => {
    const home = fixture();
    const r = run(home, []);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Usage:');
    expect(fs.existsSync(path.join(home, '.node9/config.json'))).toBe(false);
  });
  it('init --skip-setup creates config without asking any question', () => {
    const home = fixture();
    const r = run(home, ['init', '--skip-setup']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(fs.existsSync(path.join(home, '.node9/config.json'))).toBe(true);
    expect(r.stdout).not.toContain('Send usage stats');
  });
  it('repeated noninteractive init preserves existing config bytes', () => {
    const home = fixture({ settings: { mode: 'strict', autoStartDaemon: false }, custom: 42 });
    const file = path.join(home, '.node9/config.json');
    const before = fs.readFileSync(file, 'utf8');
    const r = run(home, ['init', '--skip-setup']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(fs.readFileSync(file, 'utf8')).toBe(before);
  });
  it('explicit mode still works without a terminal', () => {
    const home = fixture({ settings: { mode: 'standard' } });
    const r = run(home, ['init', '--skip-setup', '--mode', 'audit']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(
      JSON.parse(fs.readFileSync(path.join(home, '.node9/config.json'), 'utf8')).settings.mode
    ).toBe('audit');
  });
  it('recommended init completes without agents or telemetry prompts', () => {
    const home = fixture();
    const r = run(home, ['init', '--recommended']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('No agents wired yet');
    expect(r.stdout).not.toContain('Send usage stats');
    expect(r.stdout).not.toContain('is protecting');
  });
  it('requires --force to replace malformed configuration', () => {
    const home = fixture({});
    const file = path.join(home, '.node9/config.json');
    fs.writeFileSync(file, '{broken');
    expect(run(home, ['init', '--skip-setup']).status).not.toBe(0);
    expect(fs.readFileSync(file, 'utf8')).toBe('{broken');
    const result = run(home, ['init', '--force', '--skip-setup', '--mode', 'strict']);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(fs.readFileSync(file, 'utf8')).settings.mode).toBe('strict');
  });
});
