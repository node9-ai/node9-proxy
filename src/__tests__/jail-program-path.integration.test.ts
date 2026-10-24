/**
 * node9Firewall#385 at the real hook: `node9 check --agent claude` from
 * dist/cli.js, a clean HOME and a jail of the system directories added with
 * `node9 jail add` (the setup of a user who declared everything outside the
 * project off-limits).
 *
 * Before the fix every script whose first line is `#!/usr/bin/env bash` or
 * `#!/bin/bash`, and every command that runs a program by its path, was
 * blocked as a protected-file access: the jail's bash rule matched the path
 * anywhere in the command text. Neither reads a file under the jail. What the
 * command reads (an argument, a redirect, a script handed to an interpreter)
 * still meets it.
 *
 * Requirements: `npm run build` first. Skipped on Windows.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const cliExists = fs.existsSync(CLI);
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

let room: string;
let home: string;
let project: string;

function env(): NodeJS.ProcessEnv {
  const e = { ...process.env };
  delete e.NODE9_API_KEY;
  delete e.NODE9_API_URL;
  return {
    ...e,
    HOME: home,
    USERPROFILE: home,
    NODE9_NO_AUTO_DAEMON: '1',
    NODE9_TESTING: '1',
    NO_COLOR: '1',
  };
}

function cli(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: project,
    env: env(),
  });
  expect(r.error).toBeUndefined();
  return r;
}

function check(command: string): string {
  const payload = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
    cwd: project,
    session_id: 'fw385-jail-program-path',
  };
  const r = cli(['check', '--agent', 'claude', '--ask', JSON.stringify(payload)]);
  const out = (r.stdout ?? '').trim();
  const parsed = out ? (JSON.parse(out) as { hookSpecificOutput?: Record<string, unknown> }) : {};
  return String(parsed.hookSpecificOutput?.permissionDecision ?? 'allow');
}

const SCRIPT_ENV = '#!/usr/bin/env bash\nset -euo pipefail\nfor i in 1 2 3; do echo "$i"; done\n';
const SCRIPT_BIN = '#!/bin/bash\nname="${1:-world}"\necho "Hello, $name"\n';

beforeAll(() => {
  if (!cliExists) return;
  room = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-fw385-'));
  home = path.join(room, 'home');
  project = path.join(room, 'proj');
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  for (const p of ['/bin', '/usr', '/etc']) {
    expect(cli(['jail', 'add', p]).status).toBe(0);
  }
});

afterAll(() => {
  if (room) fs.rmSync(room, { recursive: true, force: true });
});

describe('a jail of the system directories (fw#385)', () => {
  itUnix('allows a script whose first line is an interpreter line', () => {
    expect(check(SCRIPT_ENV)).toBe('allow');
    expect(check(SCRIPT_BIN)).toBe('allow');
  });

  itUnix('allows running a program by its path', () => {
    expect(check('/usr/bin/python3 app.py')).toBe('allow');
    expect(check('/bin/echo done')).toBe('allow');
  });

  itUnix('still blocks what the command reads', () => {
    expect(check('cat /usr/share/dict/words')).toBe('deny');
    expect(check(`${SCRIPT_ENV}cat /etc/os-release\n`)).toBe('deny');
    expect(check('wc -l < /etc/os-release')).toBe('deny');
    expect(check('bash /etc/profile.d/x.sh')).toBe('deny');
  });

  itUnix('a shield file written before the fix gets the same reading', () => {
    const file = path.join(home, '.node9', 'shields', 'user-jail.json');
    const def = JSON.parse(fs.readFileSync(file, 'utf-8')) as {
      smartRules: Array<{ conditions: Array<Record<string, unknown>> }>;
    };
    for (const r of def.smartRules) for (const c of r.conditions) delete c.reading;
    fs.writeFileSync(file, JSON.stringify(def, null, 2));
    expect(check(SCRIPT_ENV)).toBe('allow');
    expect(check('cat /usr/share/dict/words')).toBe('deny');
  });
});
