/**
 * Integration guard: the `check` / `log` hooks load the lean hook bundle only.
 *
 * Both hooks run on EVERY agent tool call, so their startup cost is paid per
 * call. dist/cli.js is a tiny dispatcher (src/cli-entry.ts) that loads
 * dist/cli-hook.js for the hooks and dist/cli-main.js for everything else.
 * Before the split, `check` evaluated the whole 3.4 MB CLI and required
 * execa, @inquirer/prompts, yaml, string-width and friends: ~2.5x the startup
 * time, and enough to blow the 15 s probe timeout under parallel test load.
 *
 * The guard runs the real binary with a --require preload that records every
 * CommonJS module loaded (require.cache at exit), so a new import that drags a
 * heavy dependency onto the hook path fails here instead of silently slowing
 * every tool call.
 *
 * Requires `npm run build` first.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import { builtinModules } from 'module';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { keySafeEnv } from './helpers/env';

const DIST = path.resolve(__dirname, '../../dist');
const CLI = path.join(DIST, 'cli.js');

// Every npm package the hook path may load. Adding one is a deliberate choice:
// it is paid on every agent tool call. Check its load time first
// (node --cpu-prof dist/cli.js check) and prefer a lazy import() inside the
// branch that needs it.
const HOOK_PACKAGES = new Set([
  'commander',
  'chalk',
  'mvdan-sh',
  'picomatch',
  'safe-regex2',
  'ret',
  'zod',
  'semver',
]);

let tmp: string;
let preload: string;

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`dist/cli.js not found — run 'npm run build' first`);
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-hook-entry-'));
  fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
  preload = path.join(tmp, 'record-modules.js');
  fs.writeFileSync(
    preload,
    `process.on('exit', () => {
      require('fs').writeFileSync(process.env.NODE9_TEST_MODULES_OUT,
        JSON.stringify(Object.keys(require.cache)));
    });\n`
  );
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function loadedModules(args: string[], input: string) {
  const out = path.join(tmp, `modules-${args[0]}.json`);
  fs.rmSync(out, { force: true });
  const result = spawnSync(process.execPath, ['--require', preload, CLI, ...args], {
    input,
    encoding: 'utf-8',
    timeout: 60000,
    cwd: tmp,
    env: keySafeEnv({
      HOME: tmp,
      USERPROFILE: tmp,
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
      NODE9_TEST_MODULES_OUT: out,
    }),
  });
  expect(result.error).toBeUndefined();
  const files = JSON.parse(fs.readFileSync(out, 'utf-8')) as string[];
  const packages = new Set(
    files
      .map(
        (f) =>
          f
            .split(path.sep)
            .join('/')
            .match(/node_modules\/((?:@[^/]+\/)?[^/]+)/)?.[1]
      )
      .filter(Boolean)
  );
  const bundles = files.filter((f) => path.dirname(f) === DIST).map((f) => path.basename(f));
  return { result, packages, bundles };
}

const payload = (event: string) =>
  JSON.stringify({
    hook_event_name: event,
    session_id: 'hook-entry',
    cwd: os.tmpdir(),
    tool_name: 'Bash',
    tool_input: { command: 'ls' },
    tool_response: { stdout: 'a.txt' },
  });

describe('hook entry — check/log load only the lean bundle', () => {
  it.each([
    ['check', 'PreToolUse'],
    ['log', 'PostToolUse'],
  ])('%s loads dist/cli-hook.js and no package outside the hook allowlist', (cmd, event) => {
    const { result, packages, bundles } = loadedModules([cmd], payload(event));
    expect(result.status).toBe(0);
    // An allowed Bash `ls` prints nothing: stdout stays clean for the agent.
    expect(result.stdout).toBe('');
    expect(bundles).toEqual(['cli.js', 'cli-hook.js']);
    const unexpected = [...packages].filter((p) => !HOOK_PACKAGES.has(p as string));
    expect(unexpected).toEqual([]);
  });

  it('every other command still loads the full CLI', () => {
    const { result, bundles } = loadedModules(['--version'], '');
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
    expect(bundles).toEqual(['cli.js', 'cli-main.js']);
  });

  it('dist/cli.js stays a dispatcher that requires only node builtins', () => {
    const src = fs.readFileSync(CLI, 'utf-8');
    expect(src.length).toBeLessThan(8 * 1024);
    const required = [...src.matchAll(/require\("([^"]+)"\)/g)].map((m) => m[1]);
    expect(required.filter((r) => !builtinModules.includes(r.replace(/^node:/, '')))).toEqual([]);
  });
});
