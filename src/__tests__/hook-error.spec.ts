// node9Firewall#383: the fail policy and the record of a check that was not
// performed. Both must work with nothing else loaded.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  agentFromRawPayload,
  describeHookErrorPolicy,
  eventFromRawPayload,
  HOOK_ERROR_ENV,
  readHookErrorPolicy,
  recentHookErrors,
  recordHookError,
} from '../hook-error';
import { extractManagedConfig } from '../daemon/sync';

let home: string;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-hook-error-'));
  fs.mkdirSync(path.join(home, '.node9'));
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

const writeManaged = (value: unknown) =>
  fs.writeFileSync(
    path.join(home, '.node9', 'rules-cache.json'),
    JSON.stringify({ managedConfig: { onHookError: value } })
  );
const writeLocal = (value: unknown) =>
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { onHookError: value } })
  );

describe('readHookErrorPolicy', () => {
  it('is allow when nothing asks for more', () => {
    expect(readHookErrorPolicy(home, {})).toEqual({ policy: 'allow', source: 'default' });
  });

  it('is allow when ~/.node9 does not exist', () => {
    fs.rmSync(path.join(home, '.node9'), { recursive: true });
    expect(readHookErrorPolicy(home, {})).toEqual({ policy: 'allow', source: 'default' });
  });

  const askers: [string, () => void, NodeJS.ProcessEnv][] = [
    ['workspace', () => writeManaged('block'), {}],
    ['env', () => undefined, { [HOOK_ERROR_ENV]: 'block' }],
    ['config', () => writeLocal('block'), {}],
  ];
  it.each(askers)('is block when the %s asks for it', (source, setup, env) => {
    setup();
    expect(readHookErrorPolicy(home, env)).toEqual({ policy: 'block', source });
  });

  it('cannot be loosened: an allow anywhere never overrides a block', () => {
    writeManaged('block');
    writeLocal('allow');
    expect(readHookErrorPolicy(home, { [HOOK_ERROR_ENV]: 'allow' }).policy).toBe('block');

    writeManaged('allow');
    writeLocal('block');
    expect(readHookErrorPolicy(home, { [HOOK_ERROR_ENV]: 'allow' }).policy).toBe('block');

    writeLocal('allow');
    expect(readHookErrorPolicy(home, { [HOOK_ERROR_ENV]: 'BLOCK ' }).policy).toBe('block');
  });

  it.each([true, 1, 'yes', 'blocked', ['block'], { v: 'block' }, null])(
    'reads %j as silence, not as block',
    (junk) => {
      writeManaged(junk);
      writeLocal(junk);
      expect(readHookErrorPolicy(home, {}).policy).toBe('allow');
    }
  );

  it('survives files that are not what they should be', () => {
    fs.writeFileSync(path.join(home, '.node9', 'rules-cache.json'), '{"managedConfig":');
    fs.mkdirSync(path.join(home, '.node9', 'config.json'));
    expect(readHookErrorPolicy(home, {})).toEqual({ policy: 'allow', source: 'default' });
    fs.writeFileSync(path.join(home, '.node9', 'rules-cache.json'), '[1,2]');
    expect(readHookErrorPolicy(home, { [HOOK_ERROR_ENV]: 'block' }).policy).toBe('block');
  });

  it('still honours the env variable when a file is unreadable JSON', () => {
    fs.writeFileSync(path.join(home, '.node9', 'config.json'), 'not json');
    expect(readHookErrorPolicy(home, { [HOOK_ERROR_ENV]: 'block' })).toEqual({
      policy: 'block',
      source: 'env',
    });
  });
});

describe('recordHookError', () => {
  const logPath = () => path.join(home, '.node9', 'hook-debug.log');

  it('writes one JSON line with the error and its frames, and no arguments', () => {
    const err = new TypeError('Cannot convert object to primitive value');
    recordHookError(
      'engine',
      err,
      { agent: 'Claude Code', tool: 'Bash', decision: 'allow', policySource: 'default' },
      home
    );
    const lines = fs.readFileSync(logPath(), 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(1);
    const row = JSON.parse(lines[0]);
    expect(row).toMatchObject({
      event: 'hook-error',
      stage: 'engine',
      decision: 'allow',
      agent: 'Claude Code',
      tool: 'Bash',
      error: 'TypeError: Cannot convert object to primitive value',
    });
    expect(Array.isArray(row.stack)).toBe(true);
    expect(row.stack.length).toBeGreaterThan(0);
    expect(lines[0]).not.toContain(home);
  });

  it('creates ~/.node9 when it is missing, and takes a thrown non-error', () => {
    fs.rmSync(path.join(home, '.node9'), { recursive: true });
    recordHookError('parse', 'just a string', { decision: 'deny', policySource: 'env' }, home);
    const row = JSON.parse(fs.readFileSync(logPath(), 'utf-8'));
    expect(row.error).toBe('non-error thrown: just a string');
    expect(row.stack).toEqual([]);
  });

  it('never throws when the log cannot be written', () => {
    fs.mkdirSync(logPath());
    expect(() =>
      recordHookError(
        'engine',
        new Error('x'),
        { decision: 'allow', policySource: 'default' },
        home
      )
    ).not.toThrow();
  });

  it('keeps a long, multi-line message to one bounded line', () => {
    recordHookError(
      'engine',
      new Error('line one\nline two ' + 'x'.repeat(5000)),
      { decision: 'allow', policySource: 'default' },
      home
    );
    const text = fs.readFileSync(logPath(), 'utf-8');
    expect(text.trim().split('\n')).toHaveLength(1);
    expect(JSON.parse(text).error.length).toBeLessThanOrEqual(200);
  });
});

describe('recentHookErrors', () => {
  const row = (ts: string, extra: object) =>
    JSON.stringify({ ts, tool: 'Bash', decision: 'allow', checkedBy: 'hook-error', ...extra });

  it('counts the rows since the cut, split by what happened to the call', () => {
    const now = Date.parse('2026-11-28T12:00:00Z');
    const day = 24 * 60 * 60 * 1000;
    fs.writeFileSync(
      path.join(home, '.node9', 'audit.log'),
      [
        row(new Date(now - 10 * day).toISOString(), {}), // too old
        row(new Date(now - 2 * day).toISOString(), { ruleName: 'hook-error:engine:TypeError' }),
        row(new Date(now - day).toISOString(), {
          decision: 'deny',
          ruleName: 'hook-error:parse:SyntaxError',
        }),
        JSON.stringify({ ts: new Date(now).toISOString(), checkedBy: 'local-policy' }),
        // The marker inside an argument preview is not a row of this kind.
        JSON.stringify({
          ts: new Date(now).toISOString(),
          checkedBy: 'local-policy',
          argsPreview: '"checkedBy":"hook-error"',
        }),
        '{"ts": torn',
      ].join('\n') + '\n'
    );
    expect(recentHookErrors(now - 7 * day, home)).toEqual({
      count: 2,
      stopped: 1,
      last: { ts: new Date(now - day).toISOString(), what: 'hook-error:parse:SyntaxError' },
    });
  });

  it('is zero without an audit log', () => {
    expect(recentHookErrors(0, home)).toEqual({ count: 0, stopped: 0 });
  });
});

describe('a payload that did not parse', () => {
  it('names the agent from the fields only its dialect has', () => {
    expect(agentFromRawPayload('{"turn_id":"t1","tool_name":"Bash","tool_inp')).toBe('Codex');
    expect(agentFromRawPayload('{"conversationId": "c","toolCall":{"na')).toBe('Antigravity');
    expect(agentFromRawPayload('{"hook_event_name":"PreToolUse","tool_')).toBeUndefined();
  });

  it('names the event when the text still has it', () => {
    expect(eventFromRawPayload('{"hook_event_name":"UserPromptSubmit","prompt":"abc')).toBe(
      'UserPromptSubmit'
    );
    expect(eventFromRawPayload('{"tool_name":"Bash"')).toBeUndefined();
  });
});

describe('describeHookErrorPolicy', () => {
  it('says what happens and who set it', () => {
    expect(describeHookErrorPolicy({ policy: 'allow', source: 'default' })).toContain('runs');
    expect(describeHookErrorPolicy({ policy: 'block', source: 'workspace' })).toContain(
      'stopped (set by your workspace settings)'
    );
    expect(describeHookErrorPolicy({ policy: 'block', source: 'env' })).toContain(
      'NODE9_ON_HOOK_ERROR=block'
    );
  });
});

describe('the workspace setting on its way to the cache', () => {
  it('keeps block and drops everything else', () => {
    expect(extractManagedConfig({ managedConfig: { onHookError: 'block' } })?.onHookError).toBe(
      'block'
    );
    for (const junk of ['allow', 'BLOCK', true, 1, null, { a: 1 }]) {
      expect(extractManagedConfig({ managedConfig: { onHookError: junk } })).toBeUndefined();
    }
  });

  it('counts as a managed setting on its own', () => {
    expect(extractManagedConfig({ managedConfig: { onHookError: 'block' } })).toBeDefined();
  });
});
