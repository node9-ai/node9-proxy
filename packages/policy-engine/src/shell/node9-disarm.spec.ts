// A kill aimed at node9 is a disarm; a general kill of every node process is
// not (node9Firewall#482). `pkill node` / `killall node` clear stray dev
// servers, the daemon comes back on the next tool call, and they get the
// verdict any other process kill gets. Before the fix every general row here
// returned the disarm finding.
import { describe, it, expect } from 'vitest';
import { analyzeNode9Disarm } from './node9-disarm';

const DAEMON_PID = 4242;
const finding = (command: string) => analyzeNode9Disarm(command, DAEMON_PID);

describe('aimed at node9: still a disarm', () => {
  it.each([
    'pkill node9',
    'pkill -9 node9',
    'pkill -f node9',
    'pkill -f "node9 daemon"',
    'pkill -f "cli.js daemon"',
    'pkill -f "daemon start"',
    'pkill -f "node .*daemon"',
    'pkill -f daemon',
    'pkill -f @node9/proxy',
    'killall node9',
    'killall -9 node9',
    'killall -r "node9.*"',
    'taskkill /F /IM node9.exe',
    `kill ${DAEMON_PID}`,
    `taskkill /PID ${DAEMON_PID} /F`,
    'kill $(cat ~/.node9/daemon.pid)',
    'node9 daemon stop',
    'systemctl --user stop node9-daemon',
    "sh -c 'pkill node9'",
    'sudo pkill -f "node9 daemon"',
  ])('%s', (command) => {
    expect(finding(command)?.ruleName).toBe('review-node9-disarm');
  });
});

describe('a general kill of node processes: not a disarm', () => {
  it.each([
    'pkill node',
    'pkill -9 node',
    'pkill -f node',
    'pkill -f "node "',
    'pkill -f "^node"',
    'pkill nod',
    'pkill -f js',
    'pkill -f "node.*js"',
    'killall node',
    'killall -9 node',
    'killall -r "node.*"',
    'taskkill /F /IM node.exe',
    "sh -c 'pkill node'",
    'sudo pkill node',
  ])('%s', (command) => {
    expect(finding(command)).toBeNull();
  });
});

describe('unrelated kills were never a disarm', () => {
  it.each([
    'pkill python',
    'pkill -f vite',
    'pkill -f "node server.js"',
    'killall Finder',
    'kill 1234',
  ])('%s', (command) => {
    expect(finding(command)).toBeNull();
  });
});
