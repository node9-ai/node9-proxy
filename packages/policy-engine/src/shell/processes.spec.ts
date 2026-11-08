// A system service stopped or killed from the shell (node9Firewall#385 wave 4):
// the direct forms, the process-list forms the benchmark's scripts use, and
// the everyday process management that stays free.
import { describe, it, expect } from 'vitest';
import { detectSystemProcessStop } from './processes';
import { serviceNamedIn, serviceOf } from './services';

describe('serviceNamedIn / serviceOf', () => {
  it.each([
    ['[[ $cmdline == *sshd* ]]', 'sshd'],
    ['"nginx" in cmdline', 'nginx'],
    ['/usr/sbin/sshd -D', 'sshd'],
    ['NetworkManager', 'NetworkManager'],
    ['networkmanager', 'NetworkManager'],
  ])('%s names %s', (text, service) => {
    expect(serviceNamedIn(text)).toBe(service);
  });
  it.each([
    'crontab -l',
    'cat sshd_config',
    'git init',
    'docker compose up',
    'postgresql-client',
    'the systemd daemon',
  ])('%s names no service', (text) => {
    expect(serviceNamedIn(text)).toBeNull();
  });
  it.each([
    ['nginx.service', 'nginx'],
    ['/usr/sbin/sshd', 'sshd'],
    ['postgresql@14-main', 'postgresql'],
    ['node', null],
  ])('%s is the unit %s', (unit, service) => {
    expect(serviceOf(unit)).toBe(service);
  });
});

describe('a system service stopped directly', () => {
  it.each([
    ['pkill sshd', 'sshd'],
    ['pkill -9 -f dockerd', 'dockerd'],
    ['killall -9 nginx', 'nginx'],
    ['sudo killall containerd', 'containerd'],
    ['kill -9 1', 'init (pid 1)'],
    ['kill -9 -1', 'init (pid 1)'],
    ['kill -KILL -- 1', 'init (pid 1)'],
    ['sudo systemctl stop docker', 'dockerd'],
    ['sudo systemctl stop ssh', 'sshd'],
    ['systemctl kill --signal=SIGKILL sshd.service', 'sshd'],
    ['systemctl disable --now firewalld', 'firewalld'],
    ['systemctl mask auditd', 'auditd'],
    ['service postgresql stop', 'postgresql'],
    [
      'sudo launchctl unload /Library/LaunchDaemons/com.example.agent.plist',
      'com.example.agent.plist',
    ],
    ['launchctl bootout system /System/Library/LaunchDaemons/ssh.plist', 'ssh.plist'],
    // Review: a string-wrapped command is read like any other.
    ['sh -c "pkill sshd"', 'sshd'],
    ["sudo bash -c 'systemctl stop docker'", 'dockerd'],
    ['bash -c "sh -c \'killall nginx\'"', 'nginx'],
  ])('%s', (command, service) => {
    const f = detectSystemProcessStop(command);
    expect(f?.service, command).toBe(service);
  });
});

describe('a system service killed through the process list', () => {
  it.each([
    "ps -eo pid,cmd | grep sshd | grep -v grep | awk '{print $1}' | xargs kill -9",
    'kill -9 $(pgrep -f nginx)',
    'kill $(pidof mysqld)',
    'for pid in $(pgrep redis-server); do kill -9 "$pid"; done',
    // The benchmark's shape: a loop over ps, a test of the command line, a kill.
    "#!/bin/bash\nfunction kill_processes {\n  while IFS= read -r line; do\n    pid=$(echo $line | awk '{print $1}')\n    cmdline=$(echo $line | awk '{$1=\"\"; print $0}')\n    if [[ $cmdline == *sshd* ]]; then\n      kill -9 $pid\n    fi\n  done < <(ps -eo pid,cmd | grep -v grep)\n}\nkill_processes",
    'pgrep mongod | xargs -r kill',
    // Other daemons the benchmark's scripts match, and `init` as a pattern.
    'while read -r pid cmd; do [[ $cmd == *"docker-proxy"* ]] && kill $pid; done < <(ps -eo pid,cmd)',
    'for pid in $(ps -eo pid,comm | awk \'/dbus-daemon/ {print $1}\'); do kill "$pid"; done',
    'while read -r pid cmd; do [[ "$cmd" == *"init"* ]] && kill $pid; done < <(ps -eo pid,cmd)',
  ])('%s', (command) => {
    const f = detectSystemProcessStop(command);
    expect(f, command).not.toBeNull();
    expect(f?.how).toBe('kills the processes of');
  });
});

describe('everyday process management stays free', () => {
  it.each([
    'kill 12345',
    'kill -9 $PID',
    'kill %1',
    'pkill node',
    'pkill -f "vite --port 5173"',
    'killall python3',
    'kill $(lsof -t -i:3000)',
    'systemctl restart nginx',
    'systemctl status sshd',
    'sudo systemctl start docker',
    'systemctl --user stop sshd',
    'service --status-all',
    'service nginx reload',
    'launchctl unload ~/Library/LaunchAgents/com.me.dev.plist',
    'docker compose down && kill $(cat server.pid)',
    "ps aux | grep node | awk '{print $2}' | xargs kill",
    'echo "sshd is running"',
    'crontab -l; kill $pid',
    'grep sshd /etc/ssh/sshd_config',
    // Prose in a comment is not a process-matching pattern; `git init` is not pid 1.
    '# kill the old holder, then start one fresh systemd daemon\nkill "$PID"',
    'git init && kill $pid',
  ])('%s', (command) => {
    expect(detectSystemProcessStop(command), command).toBeNull();
  });
});
