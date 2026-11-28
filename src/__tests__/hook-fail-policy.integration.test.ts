/**
 * node9Firewall#383: what `node9 check` does when node9 itself fails on a call.
 *
 * Spawns the built hook with an isolated HOME. Before this change every case
 * below ended in a silent exit 0: the call ran, nothing was recorded.
 *
 * Requires `npm run build` (dist/cli.js).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let home: string;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-fail-policy-'));
  fs.mkdirSync(path.join(home, '.node9'));
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

function run(
  command: string,
  stdin: string,
  env: Record<string, string> = {},
  args: string[] = []
) {
  const baseEnv: Record<string, string | undefined> = { ...process.env };
  // Nothing of the developer's session may name an agent or a policy here.
  for (const k of Object.keys(baseEnv)) {
    if (/^(NODE9_|CLAUDE|CODEX|GEMINI|CURSOR|HERMES|ANTIGRAVITY|AIDER)/.test(k)) delete baseEnv[k];
  }
  const r = spawnSync(process.execPath, [CLI, command, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(),
    input: stdin,
    env: {
      ...baseEnv,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NODE_DISABLE_COMPILE_CACHE: '1',
      NO_COLOR: '1',
      ...env,
    },
  });
  expect(r.error).toBeUndefined();
  expect(r.status).not.toBeNull();
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}
const check = (payload: object | string, env?: Record<string, string>, args?: string[]) =>
  run('check', typeof payload === 'string' ? payload : JSON.stringify(payload), env, args);

const jsonLines = (file: string): Record<string, unknown>[] => {
  try {
    return fs
      .readFileSync(path.join(home, '.node9', file), 'utf-8')
      .split('\n')
      .filter((l) => l.startsWith('{'))
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  } catch {
    return [];
  }
};
const hookErrorRows = () => jsonLines('audit.log').filter((r) => r.checkedBy === 'hook-error');
const hookErrorLogLines = () => jsonLines('hook-debug.log').filter((r) => r.event === 'hook-error');

const claude = (tool_input: unknown, extra: object = {}) => ({
  hook_event_name: 'PreToolUse',
  tool_use_id: 'toolu_1',
  session_id: 'sess-1',
  cwd: os.tmpdir(),
  tool_name: 'Bash',
  tool_input,
  ...extra,
});
const BLOCKED = 'rm -rf ~/';
const ENGINE_FAULT = { NODE9_TEST_HOOK_FAULT: 'engine' };
const STRICT = { NODE9_ON_HOOK_ERROR: 'block' };

describe('step 0: arguments an agent can write must not make the hook throw', () => {
  it('stops the command on its own (baseline)', () => {
    expect(check(claude({ command: BLOCKED })).status).toBe(2);
  });

  it('still stops it beside a field nested thousands of levels deep', () => {
    const deep = '{"a":'.repeat(5000) + '1' + '}'.repeat(5000);
    const payload = JSON.stringify(claude({ command: BLOCKED, description: '@@' })).replace(
      '"@@"',
      deep
    );
    const r = check(payload);
    expect(r.status).toBe(2);
    expect(r.stdout).toContain('"decision":"block"');
    expect(hookErrorRows()).toEqual([]);
  });

  it('still stops it beside an object that cannot be turned into a string', () => {
    const r = check(claude({ command: BLOCKED, file_path: { toString: 1, valueOf: 2 } }));
    expect(r.status).toBe(2);
    expect(hookErrorRows()).toEqual([]);
  });

  it('decides, without an error, when the command itself is such an object', () => {
    const r = check(claude({ command: { toString: 1 } }));
    expect([0, 2]).toContain(r.status);
    expect(hookErrorRows()).toEqual([]);
    expect(hookErrorLogLines()).toEqual([]);
  });

  it.each([5, true, { a: 1 }, ['Bash']])('reads a tool name that is %j as missing', (name) => {
    const r = check(claude({ command: 'ls' }, { tool_name: name }));
    expect(r.status).toBe(2);
    expect(r.stdout).toContain('tool name missing');
    expect(hookErrorRows()).toEqual([]);
  });

  it.each(['null', '5', '"text"', '[1,2]'])('reads the payload %s as unrecognised', (raw) => {
    const r = check(raw);
    expect(r.status).toBe(2);
    expect(r.stdout).toContain('tool name missing');
    expect(hookErrorRows()).toEqual([]);
  });
});

describe('a failed check is never silent', () => {
  it('default policy: the call runs, and one audit row and one log line say it was not checked', () => {
    const r = check(claude({ command: 'ls -la' }), ENGINE_FAULT);
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).toBe('');

    const rows = hookErrorRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      tool: 'Bash',
      decision: 'allow',
      checkedBy: 'hook-error',
      ruleName: 'hook-error:engine:Error',
      agent: 'Claude Code',
      sessionId: 'sess-1',
    });
    expect(typeof rows[0].eid).toBe('string');

    // Written without NODE9_DEBUG.
    const lines = hookErrorLogLines();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      stage: 'engine',
      decision: 'allow',
      policySource: 'default',
      tool: 'Bash',
      error: 'Error: test fault: engine',
    });
  });

  it('a payload that is not JSON gets the same record, with the error class only in the row', () => {
    const r = check(
      '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sec'
    );
    expect(r.status).toBe(0);
    const rows = hookErrorRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ decision: 'allow', ruleName: 'hook-error:parse:SyntaxError' });
    // The row is shipped: nothing of the payload's text is in it.
    expect(JSON.stringify(rows[0])).not.toContain('sec');
    expect(hookErrorLogLines()[0]).toMatchObject({ stage: 'parse' });
  });

  it('an error no try caught goes the same way, not out as exit 1', () => {
    const r = check(claude({ command: 'ls' }), { NODE9_TEST_HOOK_FAULT: 'unhandled' });
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    expect(hookErrorRows()).toHaveLength(1);
    expect(hookErrorLogLines()[0]).toMatchObject({ error: 'Error: test fault: unhandled' });
  });
});

describe('policy block: the call is stopped, in the shape each agent honours', () => {
  it('Claude Code: exit 2 and a block decision that says it is not a judgement', () => {
    const r = check(claude({ command: 'ls' }), { ...ENGINE_FAULT, ...STRICT });
    expect(r.status).toBe(2);
    expect(r.stderr).toBe('');
    const out = JSON.parse(r.stdout) as {
      decision: string;
      reason: string;
      systemMessage?: string;
      hookSpecificOutput: { permissionDecision: string };
    };
    expect(out.decision).toBe('block');
    expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(out.reason).toContain('could not check this call');
    expect(out.reason).toContain('not a judgement about the call');
    expect(out.systemMessage).toContain('Node9 stopped `Bash`');
    expect(hookErrorRows()[0]).toMatchObject({ decision: 'deny', checkedBy: 'hook-error' });
    expect(hookErrorLogLines()[0]).toMatchObject({ decision: 'deny', policySource: 'env' });
  });

  it('GitHub Copilot: the flat deny, exit 0', () => {
    const r = check(claude({ command: 'ls' }), { ...ENGINE_FAULT, ...STRICT }, [
      '--agent',
      'copilot',
    ]);
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout) as { permissionDecision: string };
    expect(out.permissionDecision).toBe('deny');
    expect(hookErrorRows()[0]).toMatchObject({ decision: 'deny', agent: 'GitHub Copilot' });
  });

  it('Codex: the reason on stderr, exit 2, nothing on stdout', () => {
    const r = check(claude({ command: 'ls' }, { turn_id: 'turn-1' }), {
      ...ENGINE_FAULT,
      ...STRICT,
    });
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('could not check this call');
  });

  it('Antigravity: decision deny, exit 0', () => {
    const r = check(
      {
        conversationId: 'conv-1',
        workspacePaths: [os.tmpdir()],
        toolCall: { name: 'run_command', args: { CommandLine: 'ls' } },
      },
      { ...ENGINE_FAULT, ...STRICT }
    );
    expect(r.status).toBe(0);
    expect((JSON.parse(r.stdout) as { decision: string }).decision).toBe('deny');
    expect(hookErrorRows()[0]).toMatchObject({ tool: 'Bash', agent: 'Antigravity' });
  });

  it('a Codex payload that did not parse is still stopped the way Codex reads', () => {
    const r = check(
      '{"hook_event_name":"PreToolUse","turn_id":"t","tool_name":"Bash","tool_inp',
      STRICT
    );
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('could not check this call');
  });

  it('the workspace setting stops the call and an env allow cannot undo it', () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'rules-cache.json'),
      JSON.stringify({ managedConfig: { locked: [], onHookError: 'block' } })
    );
    const r = check(claude({ command: 'ls' }), { ...ENGINE_FAULT, NODE9_ON_HOOK_ERROR: 'allow' });
    expect(r.status).toBe(2);
    expect(hookErrorLogLines()[0]).toMatchObject({ policySource: 'workspace' });
  });

  it("the user's own config can ask for it too", () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { onHookError: 'block' } })
    );
    const r = check(claude({ command: 'ls' }), ENGINE_FAULT);
    expect(r.status).toBe(2);
    expect(r.stderr).toBe('');
    expect(hookErrorLogLines()[0]).toMatchObject({ policySource: 'config' });
  });

  it("a project's node9.config.json cannot turn it on or off", () => {
    const project = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-fail-project-'));
    try {
      fs.writeFileSync(
        path.join(project, 'node9.config.json'),
        JSON.stringify({ settings: { onHookError: 'block' } })
      );
      const r = check(claude({ command: 'ls' }, { cwd: project }), ENGINE_FAULT);
      expect(r.status).toBe(0);
    } finally {
      fs.rmSync(project, { recursive: true, force: true });
    }
  });

  it('a call that checks fine is not touched by the setting', () => {
    const r = check(claude({ command: 'ls' }), STRICT);
    expect(r.status).toBe(0);
    expect(hookErrorRows()).toEqual([]);
  });
});

describe('only a tool call is ever stopped', () => {
  const prompt = { hook_event_name: 'UserPromptSubmit', session_id: 'sess-1', prompt: 'hello' };

  it("a failed prompt check lets the person's prompt through under block, and records it", () => {
    const r = check(prompt, { NODE9_TEST_HOOK_FAULT: 'prompt', ...STRICT });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    const rows = hookErrorRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tool: 'UserPromptSubmit', decision: 'allow' });
    // The prompt's text is never in the row.
    expect(JSON.stringify(rows[0])).not.toContain('hello');
    expect(hookErrorLogLines()[0]).toMatchObject({ policySource: 'not-a-tool-call' });
  });

  it('the same for a prompt payload that did not parse', () => {
    const r = check('{"hook_event_name":"UserPromptSubmit","prompt":"hel', STRICT);
    expect(r.status).toBe(0);
    expect(hookErrorRows()[0]).toMatchObject({ decision: 'allow' });
  });
});

describe('node9 doctor', () => {
  const doctor = (env?: Record<string, string>) => run('doctor', '', env);

  it('names the default policy and stays quiet when no check failed', () => {
    const r = doctor();
    expect(r.stdout).toContain('If node9 itself fails on a call, the call runs');
    expect(r.stdout).not.toContain('not checked in the last 7 days');
  });

  it('names who set block, and counts the calls that were not checked', () => {
    check(claude({ command: 'ls' }), ENGINE_FAULT);
    check(claude({ command: 'ls' }), { ...ENGINE_FAULT, ...STRICT });
    const r = doctor(STRICT);
    expect(r.stdout).toContain('the call is stopped (set by NODE9_ON_HOOK_ERROR=block)');
    expect(r.stdout).toContain(
      '2 calls were not checked in the last 7 days because node9 failed (1 ran, 1 stopped)'
    );
    expect(r.stdout).toContain('hook-error:engine:Error');
  });
});

describe('the after-run hook reads the same safe copy', () => {
  it('records a call whose arguments are nested thousands of levels deep', () => {
    const deep = '{"a":'.repeat(5000) + '1' + '}'.repeat(5000);
    const payload = JSON.stringify({
      hook_event_name: 'PostToolUse',
      tool_use_id: 'toolu_2',
      session_id: 'sess-1',
      cwd: os.tmpdir(),
      tool_name: 'Bash',
      tool_input: { command: 'ls', description: '@@' },
      tool_response: { stdout: 'ok', stderr: '' },
    }).replace('"@@"', deep);
    const r = run('log', payload);
    expect(r.status).toBe(0);
    expect(r.stderr).not.toContain('audit log error');
  });

  it.each(['null', '7', '[]'])('ends quietly on the payload %s', (raw) => {
    const r = run('log', raw);
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    expect(jsonLines('audit.log')).toEqual([]);
  });
});

describe('phase 3: a call whose before-run hook never finished', () => {
  const HOUR = 60 * 60 * 1000;
  const journalDir = () => path.join(home, '.node9', 'checked-calls');
  /** The journal began two hours ago, so it speaks for every call since. */
  const settleJournal = () => {
    fs.mkdirSync(journalDir(), { recursive: true });
    fs.writeFileSync(path.join(journalDir(), 'since'), String(Date.now() - 2 * HOUR));
  };
  const after = (extra: object = {}) => ({
    hook_event_name: 'PostToolUse',
    tool_use_id: 'toolu_1',
    session_id: 'sess-1',
    cwd: os.tmpdir(),
    tool_name: 'Bash',
    tool_input: { command: 'ls -la' },
    tool_response: { stdout: 'ok', stderr: '' },
    ...extra,
  });
  const log = (payload: object) => run('log', JSON.stringify(payload));

  it('a call that was checked and then ran leaves no such row', () => {
    settleJournal();
    expect(check(claude({ command: 'ls -la' })).status).toBe(0);
    expect(log(after()).status).toBe(0);
    expect(hookErrorRows()).toEqual([]);
  });

  it('any verdict counts as checked: a call that was stopped, a check that failed', () => {
    settleJournal();
    expect(check(claude({ command: BLOCKED })).status).toBe(2);
    check(claude({ command: 'ls' }, { tool_use_id: 'toolu_2' }), ENGINE_FAULT);
    log(after());
    log(after({ tool_use_id: 'toolu_2' }));
    // The failed check left its own row; the after-run hook adds none.
    expect(hookErrorRows().map((r) => r.ruleName)).toEqual(['hook-error:engine:Error']);
  });

  it('a call that ran with no before-run verdict is recorded as not checked', () => {
    settleJournal();
    // Another call was checked, so the journal exists; this one never was.
    check(claude({ command: 'ls' }, { tool_use_id: 'toolu_other' }));
    const r = log(after());
    expect(r.status).toBe(0);
    const rows = hookErrorRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      tool: 'Bash',
      decision: 'allow',
      checkedBy: 'hook-error',
      ruleName: 'hook-error:no-verdict',
      agent: 'Claude Code',
      sessionId: 'sess-1',
    });
    // The hash of the arguments, no preview: nothing scanned them.
    expect(rows[0].argsPreview).toBeUndefined();
    expect(hookErrorLogLines()[0]).toMatchObject({ stage: 'no-verdict', decision: 'allow' });
  });

  it.each(['SIGTERM', 'SIGKILL'] as const)(
    'a hook the host kills with %s mid-check leaves no note, so the run is reported',
    async (signal) => {
      settleJournal();
      const baseEnv: Record<string, string | undefined> = { ...process.env };
      for (const k of Object.keys(baseEnv)) {
        if (/^(NODE9_|CLAUDE|CODEX|GEMINI|CURSOR|HERMES|ANTIGRAVITY|AIDER)/.test(k))
          delete baseEnv[k];
      }
      const child = spawn(process.execPath, [CLI, 'check'], {
        cwd: os.tmpdir(),
        stdio: ['pipe', 'ignore', 'ignore'],
        env: {
          ...baseEnv,
          HOME: home,
          USERPROFILE: home,
          NODE9_TESTING: '1',
          NODE9_NO_AUTO_DAEMON: '1',
          NODE_DISABLE_COMPILE_CACHE: '1',
          NODE9_TEST_HOOK_FAULT: 'hang',
        },
      });
      child.stdin.end(JSON.stringify(claude({ command: 'ls -la' })));
      const exited = new Promise<void>((resolve) => child.on('close', () => resolve()));
      // Long enough for the hook to be inside the check, which then never ends.
      await new Promise((resolve) => setTimeout(resolve, 2500));
      child.kill(signal);
      await exited;
      expect(fs.existsSync(path.join(journalDir(), 'current.log'))).toBe(false);

      expect(log(after()).status).toBe(0);
      expect(hookErrorRows()).toHaveLength(1);
      expect(hookErrorRows()[0]).toMatchObject({ ruleName: 'hook-error:no-verdict' });
    }
  );

  it('says nothing while the journal is new: the check may have run before it existed', () => {
    check(claude({ command: 'ls' }, { tool_use_id: 'toolu_other' }));
    log(after());
    expect(hookErrorRows()).toEqual([]);
  });

  it('says nothing on a machine that has never kept the journal', () => {
    log(after());
    expect(hookErrorRows()).toEqual([]);
  });

  it('says nothing for an agent whose after-run event is not proof of a run', () => {
    settleJournal();
    check(claude({ command: 'ls' }, { tool_use_id: 'toolu_other' }));
    run(
      'log',
      JSON.stringify({
        conversationId: 'conv-1',
        workspacePaths: [os.tmpdir()],
        toolCall: { name: 'run_command', args: { CommandLine: 'ls' } },
      })
    );
    expect(hookErrorRows()).toEqual([]);
  });

  it('doctor counts it with the other calls that were not checked', () => {
    settleJournal();
    check(claude({ command: 'ls' }, { tool_use_id: 'toolu_other' }));
    log(after());
    const r = run('doctor', '');
    expect(r.stdout).toContain('1 call was not checked in the last 7 days');
    expect(r.stdout).toContain('hook-error:no-verdict');
  });
});
