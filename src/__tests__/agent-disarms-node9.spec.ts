// The agent must not be able to switch node9 off with an ordinary call
// (node9Firewall#445 follow-up). Measured 2026-11-07, at Standard and at
// Strict: `node9 daemon stop`, killing the daemon, stopping its service and
// writing node9's own files were all allowed, and a stopped daemon quietly
// turns the outside-content check off. All of them are commands.node9-disarm:
// review at Standard, block at Strict (Audit records it, as every check).
// Design: docs/roadmap/active/agent-disarms-node9-code-design.md.
//
// Rows assert at explainPolicy, which runs the file gate and the engine the
// way the hook does.
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { explainPolicy } from '../policy';
import { _resetConfigCache } from '../config';

const DAEMON_PID = 4242;
const home = os.homedir();
const node9Dir = path.join(home, '.node9');

function setLevel(mode: string): void {
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), JSON.stringify({ settings: { mode } }));
  _resetConfigCache();
}

beforeEach(() => {
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(
    path.join(node9Dir, 'daemon.pid'),
    JSON.stringify({ pid: DAEMON_PID, port: 7391, internalToken: 'x' })
  );
  setLevel('standard');
});

const bash = async (command: string) => (await explainPolicy('Bash', { command })).decision;

const HELD = [
  'node9 daemon stop',
  'npx node9 daemon stop',
  'sudo node9 daemon stop',
  'node9 daemon uninstall',
  'node9 uninstall',
  'cd /tmp && node9 daemon stop',
  "sh -c 'node9 daemon stop'",
  'f(){ node9 daemon stop; }; f',
  `kill ${DAEMON_PID}`,
  `kill -9 ${DAEMON_PID}`,
  `kill -s TERM ${DAEMON_PID}`,
  'kill $(jq .pid ~/.node9/daemon.pid)',
  'kill "$(cat ~/.node9/daemon.pid | jq -r .pid)"',
  'pkill -f "node9 daemon"',
  'pkill -f node9',
  'pkill -f daemon',
  'pkill node',
  'killall node',
  'killall -9 node',
  'systemctl --user stop node9-daemon',
  'systemctl --user disable --now node9-daemon.service',
  'systemctl --user mask node9-daemon',
  'launchctl bootout gui/501/ai.node9.daemon',
  'launchctl unload ~/Library/LaunchAgents/ai.node9.daemon.plist',
  'taskkill /F /IM node.exe',
  `taskkill /PID ${DAEMON_PID} /F`,
];

// The file gate's half. On Windows the protected-file gate does not run at
// all (prepareFileAccesses returns no accesses there), so these rows are
// POSIX only, like the gate's other tests.
const HELD_FILES = [
  "echo '{}' > ~/.node9/config.json",
  'sed -i s/strict/audit/ ~/.node9/config.json',
  'echo {} > ~/.node9/daemon.pid',
  'rm ~/.node9/daemon.key',
  'mv ~/.node9 /tmp/n9-old',
  'cp /tmp/x.json ~/.node9/config.json',
];
const posix = it.skipIf(process.platform === 'win32');

const ALLOWED = [
  'node9 daemon restart',
  'node9 daemon start',
  'node9 daemon status',
  'node9 status',
  'node9 explain bash "ls"',
  'cat ~/.node9/audit.log',
  'tail -n 50 ~/.node9/hook-debug.log',
  'ls -la ~/.node9',
  'grep mode ~/.node9/config.json',
  'kill 1234',
  'kill %1',
  // A test HOME's daemon, not the user's (found in the real-command check).
  'H=$(mktemp -d); kill $(jq .pid $H/.node9/daemon.pid)',
  'kill "$(cat /tmp/n9b/home/.node9/daemon.pid | jq -r .pid)"',
  'pkill -f vite',
  'pkill -f "next dev"',
  'pkill -f "node server.js"',
  'pkill python',
  'killall Finder',
  'systemctl --user stop myapp',
  'systemctl --user status node9-daemon',
  'launchctl list',
  'taskkill /IM python.exe',
  'echo note > ~/.node9-notes.txt',
];

describe('switching node9 off is held (commands.node9-disarm)', () => {
  it.each(HELD)('review at Standard: %s', async (command) => {
    expect(await bash(command)).toBe('review');
  });

  it.each(HELD)('block at Strict: %s', async (command) => {
    setLevel('strict');
    expect(await bash(command)).toBe('block');
  });

  posix.each(HELD_FILES)('file: review at Standard: %s', async (command) => {
    expect(await bash(command)).toBe('review');
  });

  posix.each(HELD_FILES)('file: block at Strict: %s', async (command) => {
    setLevel('strict');
    expect(await bash(command)).toBe('block');
  });

  posix('a file tool writing node9 files is held too', async () => {
    const file = path.join(node9Dir, 'config.json');
    expect((await explainPolicy('Write', { file_path: file, content: '{}' })).decision).toBe(
      'review'
    );
    expect(
      (
        await explainPolicy('Edit', {
          file_path: file,
          old_string: 'standard',
          new_string: 'audit',
        })
      ).decision
    ).toBe('review');
    expect((await explainPolicy('Read', { file_path: file })).decision).toBe('allow');
  });

  it('the reason names node9 being switched off', async () => {
    const r = await explainPolicy('Bash', { command: 'node9 daemon stop' });
    expect(`${r.blockedByLabel} ${r.ruleDescription}`).toMatch(/node9/i);
  });
});

describe('everyday commands stay allowed', () => {
  it.each(ALLOWED)('%s', async (command) => {
    expect(await bash(command)).toBe('allow');
  });

  it('with no daemon.pid, a kill of a number is not read as the daemon', async () => {
    fs.rmSync(path.join(node9Dir, 'daemon.pid'));
    expect(await bash(`kill ${DAEMON_PID}`)).toBe('allow');
  });
});
