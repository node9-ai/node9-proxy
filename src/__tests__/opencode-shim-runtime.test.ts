/**
 * Runs the generated OpenCode shim (issue #480) the way each OpenCode major
 * drives it, against a fake node9 CLI, and asserts the verdicts land:
 *
 *   • OpenCode 1.x — default.server(input) returns tool.execute.before /
 *     tool.execute.after / chat.message hooks.
 *   • OpenCode 2.x — default.setup(host) registers host.tool.hook(
 *     "execute.before" | "execute.after") and host.session.hook("prompt").
 *     The pre-#480 shim had no setup(), so OpenCode 2 refused to load it.
 *
 * The fake CLI is a real subprocess, so the async spawn path, exit codes and
 * stdout parsing are exercised for real.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { createRequire } from 'module';
import { pathToFileURL } from 'url';
import { renderOpencodeShim } from '../setup-opencode-shim';

/* eslint-disable @typescript-eslint/no-explicit-any */

// Fake node9 CLI. check: exit 2 with a reason when the payload mentions
// DENYME, else exit 0. log --redact-output: replaces SECRET123. Every call is
// appended to calls.jsonl so tests can read the payload node9 received.
const FAKE_CLI = `
const fs = require('fs');
const path = require('path');
const args = process.argv.slice(2);
let input = '';
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', () => {
  fs.appendFileSync(path.join(__dirname, 'calls.jsonl'), JSON.stringify({ args, payload: JSON.parse(input) }) + '\\n');
  if (args[0] === 'check') {
    if (input.includes('DENYME')) {
      process.stdout.write(JSON.stringify({ decision: 'block', reason: 'denied by test' }));
      process.exit(2);
    }
    process.exit(0);
  }
  if (args[0] === 'log') {
    const out = JSON.parse(input).tool_response.output;
    const found = out.includes('SECRET123') ? ['test-secret'] : [];
    process.stdout.write(JSON.stringify({ redacted: out.split('SECRET123').join('[REDACTED]'), found }));
    process.exit(0);
  }
  process.exit(1);
});
`;

let dir: string;
let shim: any;
let deadShim: any;

function calls(): Array<{ args: string[]; payload: any }> {
  const file = path.join(dir, 'calls.jsonl');
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf-8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));
}

function resetCalls(): void {
  fs.rmSync(path.join(dir, 'calls.jsonl'), { force: true });
}

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-opencode-shim-'));
  const cli = path.join(dir, 'fake-cli.js');
  fs.writeFileSync(cli, FAKE_CLI);
  fs.writeFileSync(
    path.join(dir, 'node9.js'),
    renderOpencodeShim({ node9Argv: [process.execPath, cli], version: '9.9.9' })
  );
  fs.writeFileSync(
    path.join(dir, 'dead.js'),
    renderOpencodeShim({ node9Argv: [path.join(dir, 'no-such-node9')], version: '9.9.9' })
  );
  const req = createRequire(path.join(dir, 'x.js'));
  shim = req(path.join(dir, 'node9.js'));
  deadShim = req(path.join(dir, 'dead.js'));
});

afterAll(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

/** A minimal OpenCode 2.x host: records the hooks setup() registers. */
async function v2Host(plugin: any) {
  const hooks: Record<string, (ev: any) => Promise<void>> = {};
  const host = {
    location: { directory: '/work/project' },
    tool: {
      hook: async (name: string, cb: (ev: any) => Promise<void>) => {
        hooks[`tool.${name}`] = cb;
        return { dispose: async () => {} };
      },
    },
    session: {
      hook: async (name: string, cb: (ev: any) => Promise<void>) => {
        hooks[`session.${name}`] = cb;
        return { dispose: async () => {} };
      },
    },
  };
  await plugin.setup(host);
  return hooks;
}

describe('OpenCode shim module shape', () => {
  it('imports, as OpenCode does, to a default export both loaders accept', () => {
    // OpenCode 2 on Node and OpenCode 1 on Bun both import() the file and read
    // `default`. Import it in a real Node process, not through vitest.
    const url = pathToFileURL(path.join(dir, 'node9.js')).href;
    const r = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `const m = await import(${JSON.stringify(url)}); const d = m.default;
         console.log(JSON.stringify({ id: d.id, server: typeof d.server, setup: typeof d.setup }));`,
      ],
      { encoding: 'utf-8' }
    );
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({ id: 'node9', server: 'function', setup: 'function' });
  });
});

describe('OpenCode 2.x setup()', () => {
  it('registers the pre-tool, post-tool and prompt hooks', async () => {
    const hooks = await v2Host(shim);
    expect(Object.keys(hooks).sort()).toEqual([
      'session.prompt',
      'tool.execute.after',
      'tool.execute.before',
    ]);
  });

  it('execute.before: allows a clean call and sends node9 the real tool name and input', async () => {
    resetCalls();
    const hooks = await v2Host(shim);
    await expect(
      hooks['tool.execute.before']({
        tool: 'shell',
        sessionID: 'ses_1',
        agent: 'build',
        messageID: 'msg_1',
        id: 'call_1',
        input: { command: 'echo hi' },
      })
    ).resolves.toBeUndefined();
    const [c] = calls();
    expect(c.args).toEqual(['check']);
    expect(c.payload).toMatchObject({
      hook_event_name: 'PreToolUse',
      tool_name: 'shell',
      tool_input: { command: 'echo hi' },
      session_id: 'ses_1',
      cwd: '/work/project',
      meta: { agent: 'Opencode' },
    });
  });

  it('execute.before: a node9 deny throws with node9 reason (OpenCode turns it into a Tool.Error)', async () => {
    const hooks = await v2Host(shim);
    await expect(
      hooks['tool.execute.before']({ tool: 'shell', sessionID: 's', input: { command: 'DENYME' } })
    ).rejects.toThrow('[node9] denied by test');
  });

  it('execute.before: fails closed when the node9 binary is gone', async () => {
    const hooks = await v2Host(deadShim);
    await expect(
      hooks['tool.execute.before']({ tool: 'shell', sessionID: 's', input: { command: 'ls' } })
    ).rejects.toThrow('[node9]');
  });

  it('execute.before: an input JSON cannot encode is refused at once, not after the timeout', async () => {
    const hooks = await v2Host(shim);
    const started = Date.now();
    await expect(
      hooks['tool.execute.before']({ tool: 'shell', sessionID: 's', input: { n: BigInt(1) } })
    ).rejects.toThrow('[node9]');
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('execute.after: redacts a secret in text content AND the shell structured output', async () => {
    resetCalls();
    const hooks = await v2Host(shim);
    const ev: any = {
      tool: 'shell',
      sessionID: 's',
      input: { command: 'cat .env' },
      status: 'completed',
      result: {
        output: { output: 'KEY=SECRET123', exitCode: 0, wallTimeSeconds: 0.1 },
        content: [{ type: 'text', text: 'KEY=SECRET123' }],
        metadata: { status: 'completed' },
      },
    };
    await hooks['tool.execute.after'](ev);
    expect(ev.result.content).toEqual([{ type: 'text', text: 'KEY=[REDACTED]' }]);
    expect(ev.result.output).toEqual({
      output: 'KEY=[REDACTED]',
      exitCode: 0,
      wallTimeSeconds: 0.1,
    });
    expect(ev.result.metadata).toEqual({ status: 'completed' });
    const [c] = calls();
    expect(c.args).toEqual(['log', '--redact-output']);
    expect(c.payload).toMatchObject({
      hook_event_name: 'PostToolUse',
      tool_name: 'shell',
      tool_input: { command: 'cat .env' },
      tool_response: { output: 'KEY=SECRET123' },
    });
  });

  it('execute.after: scans a string-content result and leaves a clean one untouched', async () => {
    const hooks = await v2Host(shim);
    const dirty: any = {
      tool: 'read',
      sessionID: 's',
      input: {},
      status: 'completed',
      result: { content: 'x SECRET123' },
    };
    await hooks['tool.execute.after'](dirty);
    expect(dirty.result.content).toBe('x [REDACTED]');

    const clean: any = {
      tool: 'read',
      sessionID: 's',
      input: {},
      status: 'completed',
      result: { content: 'fine' },
    };
    const before = clean.result;
    await hooks['tool.execute.after'](clean);
    expect(clean.result).toBe(before);
  });

  it('execute.after: never throws, even when node9 cannot run', async () => {
    const hooks = await v2Host(deadShim);
    const ev: any = {
      tool: 'shell',
      sessionID: 's',
      input: {},
      status: 'error',
      error: { message: 'x' },
    };
    await expect(hooks['tool.execute.after'](ev)).resolves.toBeUndefined();
  });

  it('prompt: a prompt node9 denies throws; a clean one passes', async () => {
    resetCalls();
    const hooks = await v2Host(shim);
    await expect(
      hooks['session.prompt']({ sessionID: 's', messageID: 'm', prompt: { text: 'hello' } })
    ).resolves.toBeUndefined();
    await expect(
      hooks['session.prompt']({ sessionID: 's', messageID: 'm', prompt: { text: 'DENYME' } })
    ).rejects.toThrow('[node9] denied by test');
    expect(calls()[0].payload).toMatchObject({
      hook_event_name: 'UserPromptSubmit',
      prompt: 'hello',
      session_id: 's',
    });
  });
});

describe('OpenCode 1.x server() (unchanged behaviour)', () => {
  it('blocks a denied call, redacts output in place, and checks prompts', async () => {
    const hooks = await shim.server({ directory: '/work/v1' });
    await expect(
      hooks['tool.execute.before'](
        { tool: 'bash', sessionID: 's', callID: 'c' },
        { args: { command: 'DENYME' } }
      )
    ).rejects.toThrow('[node9] denied by test');
    await expect(
      hooks['tool.execute.before'](
        { tool: 'bash', sessionID: 's', callID: 'c' },
        { args: { command: 'ls' } }
      )
    ).resolves.toBeUndefined();

    const out = { title: '', output: 'a SECRET123', metadata: {} };
    await hooks['tool.execute.after']({ tool: 'bash', sessionID: 's', callID: 'c', args: {} }, out);
    expect(out.output).toBe('a [REDACTED]');

    await expect(
      hooks['chat.message']({ sessionID: 's' }, { parts: [{ type: 'text', text: 'DENYME' }] })
    ).rejects.toThrow('[node9] denied by test');
  });
});
