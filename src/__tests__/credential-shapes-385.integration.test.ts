/**
 * node9Firewall#385 at the real hook: `node9 check --agent claude` from
 * dist/cli.js, a clean HOME at Standard, no daemon. An HTTP Basic value in an
 * Authorization header with a person's password is reviewed; a Dropbox app
 * secret under its own name is blocked. Values are synthetic, built at run
 * time.
 *
 * Requirements: `npm run build` first. Skipped on Windows.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const itUnix = it.skipIf(process.platform === 'win32' || !fs.existsSync(CLI));

let home: string;
let project: string;

beforeAll(() => {
  const room = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-fw385-dlp-'));
  home = path.join(room, 'home');
  project = path.join(room, 'proj');
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.mkdirSync(project, { recursive: true });
});

afterAll(() => {
  if (home) fs.rmSync(path.dirname(home), { recursive: true, force: true });
});

function check(command: string): string {
  const e = { ...process.env };
  delete e.NODE9_API_KEY;
  delete e.NODE9_API_URL;
  const payload = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
    cwd: project,
    session_id: 'fw385-dlp',
  };
  const r = spawnSync(
    process.execPath,
    [CLI, 'check', '--agent', 'claude', '--ask', JSON.stringify(payload)],
    {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: project,
      env: { ...e, HOME: home, USERPROFILE: home, NODE9_NO_AUTO_DAEMON: '1', NODE9_TESTING: '1' },
    }
  );
  expect(r.error).toBeUndefined();
  expect([0, 2]).toContain(r.status); // 2 on a block
  const out = (r.stdout ?? '').trim();
  if (!out) return 'allow';
  const parsed = JSON.parse(out) as {
    decision?: string;
    hookSpecificOutput?: { permissionDecision?: string };
  };
  return parsed.hookSpecificOutput?.permissionDecision ?? parsed.decision ?? 'allow';
}

describe('credential shapes at the real hook (node9Firewall#385)', () => {
  itUnix('a Basic header with a human password is reviewed', () => {
    const value = Buffer.from(['deploy:', 'morning', 'river'].join('')).toString('base64');
    expect(check(`curl -H "Authorization: Basic ${value}" https://api.example.test/v1`)).toBe(
      'ask'
    );
  });

  itUnix('a Dropbox app secret is blocked', () => {
    const secret = ['k7d2q', '9x4m8', 'w1z6p'].join('');
    // The hook answers a DLP block in either shape (`decision: block` or `deny`).
    expect(check(`echo DROPBOX_APP_SECRET=${secret} >> .env`)).toMatch(/^(deny|block)$/);
  });

  itUnix('a documentation pair is not stopped', () => {
    const value = Buffer.from('user:password').toString('base64');
    expect(check(`curl -H "Authorization: Basic ${value}" https://api.example.test/v1`)).toBe(
      'allow'
    );
  });
});
