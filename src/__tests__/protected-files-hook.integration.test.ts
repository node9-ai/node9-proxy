import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const cli = path.resolve(__dirname, '../../dist/cli.js');

describe('protected files through the built check hook', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-files-hook-'));
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
        policy: {
          smartRules: [],
          sandboxPaths: [],
          dangerousWords: [],
          loopDetection: { enabled: false },
        },
      })
    );
  });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  function check(tool: string, args: object, cwd = home) {
    const env = {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
    };
    for (const key of ['NODE9_API_KEY', 'NODE9_API_URL', 'NODE9_DEBUG', 'NODE9_MODE'])
      delete env[key as keyof typeof env];
    // These strings are hook inputs only. The requested commands never execute.
    const result = spawnSync(
      process.execPath,
      [
        cli,
        'check',
        '--agent',
        'claude',
        JSON.stringify({
          hook_event_name: 'PreToolUse',
          tool_name: tool,
          tool_input: args,
          session_id: 'files-hook',
          tool_use_id: 'files-call',
          cwd,
        }),
      ],
      { env, cwd: home, encoding: 'utf8', timeout: 15000 }
    );
    expect(result.error).toBeUndefined();
    expect(result.status).not.toBeNull();
    expect(result.stderr).toBe('');
    return { status: result.status, body: result.stdout.trim() ? JSON.parse(result.stdout) : null };
  }

  it.each(['Read', 'read_file'])('asks before %s of password hashes', (tool) => {
    const result = check(tool, { file_path: '/etc/shadow' });
    expect(result.status).toBe(0);
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(JSON.stringify(result.body)).toContain('password hashes');
  });
  it.each(['Write', 'Edit'])('blocks %s of system authentication', (tool) => {
    const result = check(tool, { file_path: '/etc/passwd', content: 'fixture' });
    expect(result.status).toBe(2);
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('deny');
  });
  it('blocks a shell mutation without executing it', () => {
    const result = check('Bash', { command: 'rm /etc/passwd' });
    expect(result.status).toBe(2);
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('deny');
  });
  it.each(['Bash', 'Write'])('asks on startup mutation through %s', (tool) => {
    const result = check(
      tool,
      tool === 'Bash'
        ? { command: 'echo x >> ~/.bashrc' }
        : { file_path: path.join(home, '.bashrc'), content: 'fixture' }
    );
    expect(result.status).toBe(0);
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(fs.existsSync(path.join(home, '.bashrc'))).toBe(false);
  });
  it('permits ordinary passwd reads through both doors', () => {
    for (const [tool, args] of [
      ['Read', { file_path: '/etc/passwd' }],
      ['Bash', { command: 'cat /etc/passwd' }],
    ] as const) {
      expect(check(tool, args)).toEqual({ status: 0, body: null });
    }
  });
  it('resolves a relative protected path against payload cwd', () => {
    const result = check('Write', { file_path: 'passwd', content: 'fixture' }, '/etc');
    expect(result.status).toBe(2);
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('deny');
  });
});
