/**
 * Integration test: SQL-DDL detection is AST-aware end-to-end.
 *
 * Reported false positive (from ~/.node9/hook-debug.log 2026-06-12): a read-only
 * `grep -riE "sql|mysql|drop table"` tripped review-drop-truncate-shell because
 * its regex read the grep alternation's `|` as a shell pipe (`|mysql`) and matched
 * "drop table" text. Now a DB CLI must be a real command.
 *
 * Drives the real CLI (dist/cli.js). NODE9_TESTING=1 + approvalTimeoutMs:0 so a
 * `review` resolves to no-approval-mechanism (exit 2) deterministically.
 */

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function makeHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-sql-'));
  const dir = path.join(home, '.node9');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'config.json'),
    // reviewChannel:'approver' — this test asserts a review hard-blocks (exit 2)
    // with no approver; default-on would otherwise route it to the agent's ask prompt.
    JSON.stringify({
      version: '1.0',
      settings: { mode: 'standard', approvalTimeoutMs: 0, reviewChannel: 'approver' },
    })
  );
  return home;
}

function check(home: string, command: string): number | null {
  const payload = JSON.stringify({
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  });
  const env = { ...process.env } as Record<string, string>;
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'check', payload], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(),
    env: { ...env, NODE9_NO_AUTO_DAEMON: '1', NODE9_TESTING: '1', HOME: home, USERPROFILE: home },
  });
  return r.status;
}

const homes: string[] = [];
beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`dist/cli.js missing — run \`npm run build\` first`);
});
afterEach(() => {
  for (const h of homes.splice(0)) {
    try {
      fs.rmSync(h, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});
const withHome = (): string => {
  const h = makeHome();
  homes.push(h);
  return h;
};

describe('SQL-DDL detection is AST-aware (FP fix)', () => {
  it('reviews a real psql DROP TABLE', () => {
    expect(check(withHome(), 'psql -c "DROP TABLE users"')).toBe(2);
  });

  it('reviews a real mysql TRUNCATE TABLE', () => {
    expect(check(withHome(), 'mysql -e "TRUNCATE TABLE sessions"')).toBe(2);
  });

  it('ALLOWs a grep searching for DB keywords (the reported FP)', () => {
    const cmd =
      'grep -riE "sql|postgres|mysql|drop table|database protocol" --include=*.go . 2>/dev/null | head -10';
    expect(check(withHome(), cmd)).toBe(0);
  });

  it('ALLOWs an echo mentioning DROP TABLE (no DB CLI command)', () => {
    expect(check(withHome(), 'echo "TODO: DROP TABLE old_logs someday"')).toBe(0);
  });
});
