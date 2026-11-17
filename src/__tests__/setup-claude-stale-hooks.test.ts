/**
 * Issue #480 point 3: `node9 agents add claude` left hooks from an earlier
 * install in place. setupClaude spotted node9 PreToolUse/PostToolUse hooks with
 * `includes('node9 check')`, which misses every QUOTED form
 * (`"/old/bin/node9" check`, `"/usr/bin/node" "/old/cli.js" check`). The dead
 * entries were neither recognised nor repaired, new ones were added beside
 * them, and every Claude Code tool call then failed twice.
 *
 * Runs the real setupClaude against a real temp HOME, with the production
 * command builder (NODE9_TESTING off), so the hook strings are the ones a user
 * gets.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  setupClaude,
  isNode9Hook,
  isStaleHookCommand,
  deadClaudeNode9Hooks,
  node9HookSubcommand,
} from '../setup.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

let home: string;
const fwd = (p: string): string => p.replace(/\\/g, '/');
let settingsPath: string;
const realArgv = process.argv;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-claude-stale-'));
  settingsPath = path.join(home, '.claude', 'settings.json');
  vi.spyOn(os, 'homedir').mockReturnValue(home);
  vi.stubEnv('NODE9_TESTING', '');
  vi.spyOn(console, 'log').mockImplementation(() => undefined);
  // fullPathCommand builds the hook from process.argv[1], which in production
  // is node9's dist/cli.js. Under vitest it is the worker script, and on
  // Windows (no ~/.node9/bin/hook shim) the written hook then names that
  // worker and is not a node9 command at all. Run as an installed node9 would.
  const cli = path.join(home, 'install', 'node_modules', '@node9', 'proxy', 'dist', 'cli.js');
  fs.mkdirSync(path.dirname(cli), { recursive: true });
  fs.writeFileSync(cli, '');
  process.argv = [realArgv[0], cli, ...realArgv.slice(2)];
});

afterEach(() => {
  process.argv = realArgv;
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  fs.rmSync(home, { recursive: true, force: true });
});

function writeSettings(settings: unknown): void {
  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
}

function readSettings(): any {
  return JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
}

function node9Commands(settings: any, event: string): string[] {
  return (settings.hooks?.[event] ?? []).flatMap((m: any) =>
    (m.hooks ?? []).map((h: any) => h.command).filter((c: string) => isNode9Hook(c))
  );
}

// The two dead forms from the report: a bun global bin, and node + a bun
// global cli.js. Both quoted, both pointing at files that no longer exist.
function staleForms(sub: 'check' | 'log'): string[] {
  // Forward slashes, the form node9 writes on every platform: the dead-path
  // check reads `/...` and `C:/...` tokens (a `C:\\...` token is legacy).
  const bun = fwd(path.join(home, '.bun'));
  return [
    `"${bun}/bin/node9" ${sub}`,
    `"${fwd(process.execPath)}" "${bun}/install/global/node_modules/@node9/proxy/dist/cli.js" ${sub}`,
  ];
}

function staleEvent(sub: 'check' | 'log') {
  return staleForms(sub).map((command) => ({
    matcher: '.*',
    hooks: [{ type: 'command', command, timeout: 600 }],
  }));
}

describe('setupClaude repairs hooks left by an earlier install (#480)', () => {
  it('leaves exactly one working node9 hook per event, none pointing at a missing file', async () => {
    writeSettings({
      hooks: {
        PreToolUse: staleEvent('check'),
        PostToolUse: staleEvent('log'),
        UserPromptSubmit: staleEvent('check'),
      },
    });

    await setupClaude();

    const s = readSettings();
    for (const event of ['PreToolUse', 'PostToolUse', 'UserPromptSubmit']) {
      const cmds = node9Commands(s, event);
      expect(cmds, event).toHaveLength(1);
      expect(isStaleHookCommand(cmds[0]), `${event}: ${cmds[0]}`).toBe(false);
    }
    expect(node9Commands(s, 'PostToolUse')[0]).toMatch(/ log$/);
    expect(deadClaudeNode9Hooks(s)).toEqual([]);
  });

  it('removes the dead entries that sit beside current ones (the reported state)', async () => {
    // First run on a clean HOME writes the current hooks...
    await setupClaude();
    const current = readSettings();
    const pre = node9Commands(current, 'PreToolUse')[0];
    // ...then the old install's entries are still in front of them.
    current.hooks.PreToolUse = [...staleEvent('check'), ...current.hooks.PreToolUse];
    current.hooks.PostToolUse = [...staleEvent('log'), ...current.hooks.PostToolUse];
    writeSettings(current);

    await setupClaude();

    const s = readSettings();
    expect(node9Commands(s, 'PreToolUse')).toEqual([pre]);
    expect(node9Commands(s, 'PostToolUse')).toHaveLength(1);
    // The matchers the dead entries lived in are gone, not left empty.
    expect(s.hooks.PreToolUse.every((m: any) => m.hooks.length > 0)).toBe(true);
  });

  it('keeps foreign hooks and a node9 hook under a different matcher', async () => {
    await setupClaude();
    const s0 = readSettings();
    const pre = node9Commands(s0, 'PreToolUse')[0];
    s0.hooks.PreToolUse.push(
      { matcher: 'Bash', hooks: [{ type: 'command', command: pre }] },
      { matcher: '.*', hooks: [{ type: 'command', command: 'my-own-linter --fast' }] }
    );
    writeSettings(s0);

    await setupClaude();

    const s = readSettings();
    expect(s.hooks.PreToolUse.map((m: any) => m.matcher)).toEqual(['.*', 'Bash', '.*']);
    expect(JSON.stringify(s)).toContain('my-own-linter --fast');
  });

  it('adds the PreToolUse check when the only node9 hook there is a `log`', async () => {
    writeSettings({
      hooks: {
        PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
      },
    });
    await setupClaude();
    const cmds = node9Commands(readSettings(), 'PreToolUse');
    expect(cmds.some((c) => / check$/.test(c))).toBe(true);
  });

  it('repairs a dead hook even when the event also needs a hook added, keeping its own subcommand', async () => {
    writeSettings({
      hooks: {
        PreToolUse: [
          { matcher: '.*', hooks: [{ type: 'command', command: staleForms('log')[0] }] },
        ],
      },
    });
    await setupClaude();
    const cmds = node9Commands(readSettings(), 'PreToolUse');
    expect(cmds.every((c) => !isStaleHookCommand(c))).toBe(true);
    expect(cmds.filter((c) => / check$/.test(c))).toHaveLength(1);
    // The stray `log` stays a `log`; it is not turned into a second check.
    expect(cmds.filter((c) => / log$/.test(c))).toHaveLength(1);
  });

  it('is idempotent: a second run on a current install changes nothing', async () => {
    await setupClaude();
    const first = fs.readFileSync(settingsPath, 'utf-8');
    await setupClaude();
    expect(fs.readFileSync(settingsPath, 'utf-8')).toBe(first);
    expect(node9Commands(readSettings(), 'PreToolUse')).toHaveLength(1);
  });
});

describe('node9HookSubcommand', () => {
  it('reads the subcommand of every node9 hook form and rejects foreign commands', () => {
    expect(node9HookSubcommand('node9 check')).toBe('check');
    expect(node9HookSubcommand('"/a b/bin/node9" log')).toBe('log');
    expect(node9HookSubcommand('"/usr/bin/node" "/x/dist/cli.js" check')).toBe('check');
    expect(node9HookSubcommand('"/home/u/.node9/bin/hook" log')).toBe('log');
    expect(node9HookSubcommand('mynode9 check')).toBeNull();
    expect(node9HookSubcommand('my-linter --fast')).toBeNull();
  });
});

describe('deadClaudeNode9Hooks (doctor input)', () => {
  it('lists node9 hooks whose binary is gone and ignores live and foreign ones', () => {
    const dead = staleForms('check');
    const settings = {
      hooks: {
        PreToolUse: [
          { matcher: '.*', hooks: [{ type: 'command', command: dead[0] }] },
          { matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] },
          { matcher: '.*', hooks: [{ type: 'command', command: '"/gone/tool" run' }] },
        ],
      },
    };
    expect(deadClaudeNode9Hooks(settings as any)).toEqual([dead[0]]);
  });
});
