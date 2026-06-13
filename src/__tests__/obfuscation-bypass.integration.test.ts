/**
 * Integration test: disguised destructive commands must NOT bypass the gate.
 *
 * Verified bypass (node9 v1.31.0): `r''m -rf ~` / `\rm -rf ~` ALLOWed while
 * literal `rm -rf ~` BLOCKed. Fix de-obfuscates the command token in
 * normalizeCommandForPolicy, which the smart-rule matcher already runs on the
 * `command` field. This drives the REAL CLI (dist/cli.js) end-to-end.
 *
 * Requires `npm run build` first. NODE9_TESTING=1 disables the interactive
 * approval UI and the daemon block→review downgrade, so a `block` verdict is a
 * deterministic exit 2 (no popups, no waiting).
 */

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function makeTempHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-obf-'));
  const dir = path.join(home, '.node9');
  fs.mkdirSync(dir, { recursive: true });
  // Minimal config — getConfig merges DEFAULT_CONFIG, which carries the
  // block-rm-rf-home / review-force-push smart rules and the /tmp sandbox.
  // approvalTimeoutMs:0 → no timeout racer, so a `review` verdict resolves to
  // no-approval-mechanism (exit 2) immediately instead of waiting 120s for a
  // human that never comes in this headless test.
  fs.writeFileSync(
    path.join(dir, 'config.json'),
    JSON.stringify({ version: '1.0', settings: { mode: 'standard', approvalTimeoutMs: 0 } })
  );
  return home;
}

function check(home: string, command: string): { status: number | null; stdout: string } {
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
  return { status: r.status, stdout: r.stdout ?? '' };
}

let home: string;
const homes: string[] = [];
beforeAll(() => {
  if (!fs.existsSync(CLI))
    throw new Error(`dist/cli.js missing — run \`npm run build\` first (${CLI})`);
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
  home = makeTempHome();
  homes.push(home);
  return home;
};

describe('obfuscated destructive commands are intercepted (GAP fix)', () => {
  it("BLOCKs quote-split rm (r''m -rf ~)", () => {
    const r = check(withHome(), "r''m -rf ~");
    expect(r.status).toBe(2);
  });

  it('BLOCKs backslash rm (\\rm -rf ~)', () => {
    const r = check(withHome(), '\\rm -rf ~');
    expect(r.status).toBe(2);
  });

  it('still BLOCKs literal rm -rf ~ (control)', () => {
    const r = check(withHome(), 'rm -rf ~');
    expect(r.status).toBe(2);
  });

  it("intercepts obfuscated force-push (git pu''sh --force)", () => {
    const r = check(withHome(), "git pu''sh --force origin main");
    expect(r.status).not.toBe(0); // review/block — not silently allowed
  });

  // ── Negatives: must still pass through ──
  it('ALLOWs rm -rf /tmp/test (sandbox, unchanged)', () => {
    const r = check(withHome(), 'rm -rf /tmp/test');
    expect(r.status).toBe(0);
  });

  it("ALLOWs a commit message that mentions r''m -rf (message stripped, not a command)", () => {
    const r = check(withHome(), `git commit -m "fixing the r''m -rf bug"`);
    expect(r.status).toBe(0);
  });
});
