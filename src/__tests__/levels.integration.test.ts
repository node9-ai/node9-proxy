// src/__tests__/levels.integration.test.ts
//
// The protection levels at the real gate (node9Firewall#385 item 5): the
// `check` hook against dist/cli.js, a temp HOME per level, no daemon and no
// approver, so a review surfaces as Claude's "ask". One destructive SQL
// command and one ordinary command show the ladder:
//   audit  -> allowed, recorded as observe-mode
//   soft   -> allowed, recorded against commands.sql-ddl
//   standard -> ask
//   strict -> blocked
//   block-all -> an ordinary command asks too (the catch-all)
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let root: string;

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`dist/cli.js not found at ${CLI}; run npm run build`);
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-levels-gate-'));
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function homeFor(mode: string): string {
  const home = path.join(root, mode);
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({
      settings: {
        mode,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
    })
  );
  return home;
}

function check(mode: string, command: string) {
  const home = homeFor(mode);
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  delete env.NODE9_MODE;
  const payload = {
    tool_name: 'Bash',
    tool_input: { command },
    hook_event_name: 'PreToolUse',
    cwd: root,
    session_id: 'levels-test',
  };
  const r = spawnSync(process.execPath, [CLI, 'check', JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: root,
    env: {
      ...env,
      HOME: home,
      USERPROFILE: home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
    },
  });
  const auditLog = path.join(home, '.node9', 'audit.log');
  const rows = fs.existsSync(auditLog)
    ? fs
        .readFileSync(auditLog, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as Record<string, unknown>)
    : [];
  return { ...r, stdout: r.stdout ?? '', rows };
}

const DDL = 'psql -c "DROP TABLE users"';

describe('protection levels at the gate', () => {
  it('audit: nothing is stopped, the call is recorded', () => {
    const r = check('audit', DDL);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain('"decision":"block"');
    expect(r.stdout).not.toContain('"permissionDecision":"ask"');
    expect(r.rows.some((row) => String(row.checkedBy).startsWith('observe-mode'))).toBe(true);
  });

  it('soft: the destructive SQL check only records', () => {
    const r = check('soft', DDL);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain('"permissionDecision":"ask"');
    const row = r.rows.find((x) => x.checkId === 'commands.sql-ddl');
    expect(row?.decision).toBe('allow');
  });

  it('standard: the destructive SQL check asks', () => {
    const r = check('standard', DDL);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('"permissionDecision":"ask"');
  });

  it('strict: the destructive SQL check blocks', () => {
    const r = check('strict', DDL);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(2);
    expect(r.stdout).toContain('"decision":"block"');
  });

  it('strict: an ordinary command passes; block-all asks about it', () => {
    const s = check('strict', 'ls -la');
    expect(s.error).toBeUndefined();
    expect(s.status).toBe(0);
    expect(s.stdout).not.toContain('"permissionDecision":"ask"');
    const b = check('block-all', 'ls -la');
    expect(b.error).toBeUndefined();
    expect(b.stdout).toContain('"permissionDecision":"ask"');
  });
});
