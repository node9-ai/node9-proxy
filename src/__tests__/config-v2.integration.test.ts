// The v2 config file through the built CLI (requires `npm run build`): the
// automatic one-time migration on an ordinary command, the migrate command
// with --undo, `node9 checks` naming the file as the source, the real check
// hook honouring a v2 file, a writer keeping a v2 file v2, and `node9 init`
// creating a v2 file on a new machine.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let home: string;
const cfg = () => path.join(home, '.node9', 'config.json');
const read = () => JSON.parse(fs.readFileSync(cfg(), 'utf8')) as Record<string, unknown>;

function run(args: string[], env: Record<string, string> = {}) {
  const base = { ...process.env };
  delete base.NODE9_API_KEY;
  delete base.NODE9_API_URL;
  delete base.NODE9_NO_CONFIG_MIGRATE;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60_000,
    cwd: os.tmpdir(),
    env: {
      ...base,
      HOME: home,
      USERPROFILE: home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      NODE9_TEST_CONFIG_MIGRATE: '1',
      ...env,
    },
  });
  expect(r.error, `spawn failed: ${r.error?.message}`).toBeUndefined();
  expect(r.status, 'the CLI did not exit').not.toBeNull();
  return r;
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-v2-cli-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('automatic migration', () => {
  it('an ordinary command moves a legacy file to v2 once, says so once, and keeps a backup', () => {
    fs.writeFileSync(cfg(), JSON.stringify({ version: '1.0', settings: { mode: 'strict' } }));
    const first = run(['checks']);
    expect(first.status).toBe(0);
    expect(first.stderr).toContain('moved to the new format');
    expect(read()).toEqual({ version: '2', mode: 'strict' });
    expect(
      fs.readdirSync(path.join(home, '.node9')).some((n) => n.startsWith('config.json.bak-'))
    ).toBe(true);
    const second = run(['checks']);
    expect(second.stderr).not.toContain('moved to the new format');
  });

  it('the hooks never migrate', () => {
    fs.writeFileSync(cfg(), JSON.stringify({ version: '1.0', settings: { mode: 'strict' } }));
    const r = run(['check', JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } })]);
    expect(r.status, r.stderr).not.toBeNull();
    expect(read().version).toBe('1.0');
  });
});

describe('node9 config migrate', () => {
  it('--dry-run prints, migrate writes, --undo restores the exact bytes', () => {
    const before = JSON.stringify({
      version: '1.0',
      policy: { commandChecks: { inlineExec: 'off' } },
    });
    fs.writeFileSync(cfg(), before);
    const dry = run(['config', 'migrate', '--dry-run'], { NODE9_NO_CONFIG_MIGRATE: '1' });
    expect(dry.status).toBe(0);
    expect(JSON.parse(dry.stdout)).toEqual({
      version: '2',
      checks: { 'commands.inline-exec': 'off' },
    });
    expect(fs.readFileSync(cfg(), 'utf8')).toBe(before);

    const mig = run(['config', 'migrate'], { NODE9_NO_CONFIG_MIGRATE: '1' });
    expect(mig.status, mig.stderr).toBe(0);
    expect(read()).toEqual({ version: '2', checks: { 'commands.inline-exec': 'off' } });

    const undo = run(['config', 'migrate', '--undo'], { NODE9_NO_CONFIG_MIGRATE: '1' });
    expect(undo.status, undo.stderr).toBe(0);
    expect(fs.readFileSync(cfg(), 'utf8')).toBe(before);
  });
});

describe('a v2 file in use', () => {
  it('node9 checks names the file as the source', () => {
    fs.writeFileSync(cfg(), JSON.stringify({ version: '2', checks: { 'commands.sudo': 'off' } }));
    const r = run(['checks', '--json']);
    expect(r.status, r.stderr).toBe(0);
    const report = JSON.parse(r.stdout) as {
      checks: Array<{ id: string; value: string; source: string }>;
    };
    expect(report.checks.find((c) => c.id === 'commands.sudo')).toMatchObject({
      value: 'off',
      source: 'local',
    });
  });

  it('the real check hook lets sudo through when the file says off', () => {
    fs.writeFileSync(cfg(), JSON.stringify({ version: '2', checks: { 'commands.sudo': 'off' } }));
    const payload = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'sudo true' } });
    const r = run(['check', payload]);
    expect(r.status, r.stderr).toBe(0);
    const rows = fs
      .readFileSync(path.join(home, '.node9', 'audit.log'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(rows.at(-1)).toMatchObject({ decision: 'allow' });
  });

  it('a writer keeps the file v2: node9 egress watch', () => {
    fs.writeFileSync(cfg(), JSON.stringify({ version: '2', checks: { 'commands.sudo': 'off' } }));
    const r = run(['egress', 'watch']);
    expect(r.status, r.stderr).toBe(0);
    const data = read();
    expect(data.version).toBe('2');
    expect(data.checks).toEqual({ 'commands.sudo': 'off', 'network.unknown-host': 'review' });
  });
});

describe('a new machine', () => {
  it('node9 init writes a v2 file holding only the chosen mode', () => {
    fs.rmSync(cfg(), { force: true });
    const r = run(['init', '--skip-setup', '--mode', 'strict']);
    expect(r.status, r.stderr).toBe(0);
    expect(read()).toEqual({ version: '2', mode: 'strict' });
    const again = run(['init', '--skip-setup']);
    expect(again.status, again.stderr).toBe(0);
    expect(read()).toEqual({ version: '2', mode: 'strict' });
  });
});
