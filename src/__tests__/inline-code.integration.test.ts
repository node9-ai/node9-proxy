/**
 * node9Firewall#385 at the real hook: inline code is reviewed only when it does
 * something dangerous or cannot be read. `node9 check --agent claude` and
 * `node9 explain` from dist/cli.js with a clean HOME; strict mode keeps asking
 * on every inline call.
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
let project: string;

function makeHome(mode?: string): string {
  const home = fs.mkdtempSync(path.join(room, 'home-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  if (mode) {
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { mode } })
    );
  }
  return home;
}

function cli(home: string, args: string[]) {
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: project,
    env: {
      ...env,
      HOME: home,
      USERPROFILE: home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      NO_COLOR: '1',
    },
  });
  expect(r.error).toBeUndefined();
  return r;
}

function check(home: string, command: string): { decision: string; reason: string } {
  const payload = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
    cwd: project,
    session_id: 'fw385-inline-code',
  };
  const r = cli(home, ['check', '--agent', 'claude', '--ask', JSON.stringify(payload)]);
  const out = (r.stdout ?? '').trim();
  const h = (out ? JSON.parse(out) : {}).hookSpecificOutput ?? {};
  return {
    decision: String(h.permissionDecision ?? 'allow'),
    reason: String(h.permissionDecisionReason ?? ''),
  };
}

const ORDINARY = `python3 - <<'PYEOF'\ndef add(a, b):\n    return a + b\n\nassert add(2, 3) == 5\nprint("ok")\nPYEOF`;
const DELETES = `python3 - <<'PYEOF'\nimport os\nos.remove("notes.txt")\nPYEOF`;

beforeAll(() => {
  if (!cliExists) return;
  room = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-fw385-inline-'));
  project = path.join(room, 'proj');
  fs.mkdirSync(project, { recursive: true });
});

afterAll(() => {
  if (room) fs.rmSync(room, { recursive: true, force: true });
});

describe('inline code at the real hook (fw#385)', () => {
  itUnix('ordinary inline code runs without a prompt', () => {
    const h = makeHome();
    expect(check(h, ORDINARY).decision).toBe('allow');
    expect(check(h, "node -e 'console.log(1 + 1)'").decision).toBe('allow');
  });

  itUnix('dangerous inline code is held, and the prompt names the operation', () => {
    const h = makeHome();
    const v = check(h, DELETES);
    expect(v.decision).toBe('ask');
    expect(v.reason).toContain('deletes files');
  });

  itUnix('code node9 cannot read is held', () => {
    const h = makeHome();
    expect(check(h, 'python3 -c "$CODE"').decision).toBe('ask');
  });

  itUnix('strict mode keeps asking on every inline call', () => {
    const h = makeHome('strict');
    expect(check(h, ORDINARY).decision).not.toBe('allow');
  });

  itUnix('explain agrees with the gate', () => {
    const h = makeHome();
    const ok = cli(h, ['explain', 'bash', ORDINARY]);
    expect(ok.stdout + ok.stderr).toMatch(/Decision: .*ALLOW/);
    const held = cli(h, ['explain', 'bash', DELETES]);
    expect(held.stdout + held.stderr).toMatch(/Decision: .*REVIEW/);
    expect(held.stdout + held.stderr).toContain('deletes files');
  });
});
