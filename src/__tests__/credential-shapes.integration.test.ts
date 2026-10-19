/**
 * The credential shapes added after node9Firewall#348 (an HTTP Basic value,
 * an OTP constructor secret, escaped JSON, the wider name list) on the
 * shipped binary: `node9 check --agent claude` with a Write payload, in a
 * temp HOME, approvers off. A review reaches the agent as "ask", a benign
 * look-alike as no output. Values are synthetic and assembled at runtime.
 * Requirements: `npm run build` first (dist/cli.js).
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { keySafeEnv } from './helpers/env';

const cli = path.resolve(__dirname, '../../dist/cli.js');
const itCli = it.skipIf(!fs.existsSync(cli));
const PASSWORD = ['q7Rk', '2xVm', '9pLw', '4tZb'].join('');
const BASE32 = ['KQZC', 'W4NX', 'RDTV', '6MJP'].join('');
const GENERATED = ['Ghq', 'ylh3N', 'Fbs1jC', '_26Vo', 'Q9'].join('');
let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-cred-shapes-'));
  fs.mkdirSync(path.join(home, '.node9'));
  fs.writeFileSync(
    path.join(home, '.node9/config.json'),
    JSON.stringify({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 0,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: { loopDetection: { enabled: false } },
    })
  );
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

function write(content: string) {
  const payload = JSON.stringify({
    hook_event_name: 'PreToolUse',
    tool_name: 'Write',
    tool_input: { file_path: path.join(home, 'project', 'config.yml'), content },
    session_id: 'cred-shapes',
    tool_use_id: 'cred-shapes-call',
    cwd: home,
  });
  const result = spawnSync(process.execPath, [cli, 'check', '--agent', 'claude', payload], {
    cwd: home,
    encoding: 'utf8',
    timeout: 20_000,
    env: {
      ...keySafeEnv(),
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
    },
  });
  expect(result.error).toBeUndefined();
  expect(result.status).not.toBeNull();
  expect(result.stderr).toBe('');
  return { status: result.status, body: result.stdout.trim() ? JSON.parse(result.stdout) : null };
}

describe('credential shapes through the built hook', () => {
  itCli.each([
    [
      'an HTTP Basic value',
      `auth:\n  - Basic ${Buffer.from(`svc:${PASSWORD}`).toString('base64')}`,
    ],
    ['an OTP constructor secret', `otp = ROTP::TOTP.new('${BASE32}')`],
    ['escaped JSON', `body = "{ \\"access_token\\":\\"${GENERATED}\\" }"`],
    ['a consumer key', `consumer_key: '${GENERATED}'`],
  ])('asks before writing %s, without echoing the value', (_name, content) => {
    const r = write(content);
    expect(r.status).toBe(0);
    expect(r.body.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(JSON.stringify(r.body)).not.toContain(PASSWORD);
    expect(JSON.stringify(r.body)).not.toContain(GENERATED.slice(3, -3));
  });

  itCli.each([
    ['prose about Basic auth', 'Basic authentication is enabled for the admin area.'],
    ['a reference', 'totp = pyotp.TOTP(user.otp_secret)'],
    ['a word that contains pass', `bypass: ${GENERATED}`],
  ])('allows %s', (_name, content) => {
    expect(write(content)).toEqual({ status: 0, body: null });
  });
});
