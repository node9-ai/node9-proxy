// The node9 bundles are CommonJS and require ESM-only dependencies (commander
// 15). A Node that cannot require() an ES module (18, 20 before 20.19, 22
// before 22.12) crashed on load with a stack trace and exit 1, and an agent
// whose PATH started with such a Node ran every tool call unchecked with no
// word to anyone. The launcher now says what is wrong, in one line, and logs
// it. The exit code is unchanged: the fail policy belongs to fw#383.
//
// `--no-experimental-require-module` turns the feature off on a current Node,
// which is the same state an old Node is in.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { canRequireEsm, unsupportedNodeMessage } from '../launch';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const PAYLOAD = JSON.stringify({
  hook_event_name: 'PreToolUse',
  session_id: 'old-node',
  cwd: os.tmpdir(),
  tool_name: 'Bash',
  tool_input: { command: 'ls' },
});

let home: string;

function run(nodeFlags: string[], args: string[]) {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.NODE_OPTIONS;
  const r = spawnSync(process.execPath, [...nodeFlags, CLI, ...args], {
    input: PAYLOAD,
    encoding: 'utf-8',
    timeout: 25_000,
    cwd: home,
    env: { ...env, HOME: home, USERPROFILE: home, NODE9_TESTING: '1', NODE9_NO_AUTO_DAEMON: '1' },
  });
  expect(r.error).toBeUndefined();
  return r;
}

describe('launcher on a Node that cannot require ESM', () => {
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-oldnode-'));
    fs.mkdirSync(path.join(home, '.node9'));
  });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  it('reads the feature flag, not the version string', () => {
    expect(canRequireEsm({ require_module: true })).toBe(true);
    expect(canRequireEsm({ require_module: false })).toBe(false);
    expect(canRequireEsm({})).toBe(false); // Node 18 has no such flag
  });

  it.each([['check'], ['log'], ['--version']])(
    '`%s` explains the problem in one line instead of crashing',
    (cmd) => {
      const r = run(['--no-experimental-require-module'], [cmd]);
      expect(r.status).toBe(1);
      expect(r.stdout).toBe('');
      expect(r.stderr).not.toContain('ERR_REQUIRE_ESM');
      expect(r.stderr.trim()).toBe(unsupportedNodeMessage(process.version, process.execPath));
      const log = fs.readFileSync(path.join(home, '.node9', 'hook-debug.log'), 'utf-8');
      expect(log).toContain('UNSUPPORTED NODE');
      expect(log).toContain(process.version);
    }
  );

  it('does not create ~/.node9 when node9 was never set up there', () => {
    fs.rmSync(path.join(home, '.node9'), { recursive: true });
    const r = run(['--no-experimental-require-module'], ['check']);
    expect(r.status).toBe(1);
    expect(fs.existsSync(path.join(home, '.node9'))).toBe(false);
  });

  it('control: a Node with require(esm) runs the hook as before', () => {
    const r = run([], ['check']);
    expect(r.status).toBe(0);
    expect(r.stderr).not.toContain('cannot run node9');
  });
});
