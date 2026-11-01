// fw#425: a hook call must not pay for what it does not use. The binary is a
// launcher that turns on Node's compile cache and hands `check` / `log` to a
// bundle holding only them; the shell parser loads on the first parse.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import nodeModule from 'module';
import { bundleFor, enableCompileCache } from '../launch';

const DIST = path.resolve(__dirname, '../../dist');
const CLI = path.join(DIST, 'cli.js');
const VERSION = (
  JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../package.json'), 'utf-8')) as {
    version: string;
  }
).version;

let home: string;

function run(
  args: string[],
  input?: string,
  extraEnv: Record<string, string> = {}
): { status: number | null; stdout: string; stderr: string } {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  delete env.NODE_COMPILE_CACHE;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    input,
    encoding: 'utf-8',
    timeout: 60_000,
    cwd: home,
    env: {
      ...env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      ...extraEnv,
    },
  });
  expect(r.error).toBeUndefined();
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const payload = (tool: string, input: Record<string, unknown>) =>
  JSON.stringify({ session_id: 's1', tool_name: tool, tool_input: input, cwd: home });

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-startup-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode: 'standard' } })
  );
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('launcher dispatch', () => {
  it('check and log go to the hook bundle, everything else to the full CLI', () => {
    expect(bundleFor('check')).toBe('hook.js');
    expect(bundleFor('log')).toBe('hook.js');
    for (const sub of ['status', 'scan', 'daemon', 'npx', '--version', undefined]) {
      expect(bundleFor(sub)).toBe('cli-main.js');
    }
  });

  it('the full CLI still answers through the launcher', () => {
    const r = run(['--version']);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe(VERSION);
  });

  it('check answers through the launcher with the same verdict shape', () => {
    const r = run(['check'], payload('Bash', { command: 'rm -rf /' }));
    expect(r.status).not.toBeNull();
    expect(r.stdout + r.stderr).toMatch(/deny|block/i);
  });
});

describe('compile cache', () => {
  it('a call creates the cache for this version under ~/.node9 and removes older versions', () => {
    const root = path.join(home, '.node9', 'compile-cache');
    fs.mkdirSync(path.join(root, '0.0.1-old'), { recursive: true });
    const r = run(['--version']);
    expect(r.status).toBe(0);
    const supported =
      typeof (nodeModule as unknown as { enableCompileCache?: unknown }).enableCompileCache ===
      'function';
    if (supported) {
      expect(fs.readdirSync(root)).toEqual([VERSION]);
    }
  });

  it('a cache the environment chose wins, and nothing is written under ~/.node9', () => {
    const own = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-own-cache-'));
    try {
      const r = run(['--version'], undefined, { NODE_COMPILE_CACHE: own });
      expect(r.status).toBe(0);
      expect(fs.existsSync(path.join(home, '.node9', 'compile-cache'))).toBe(false);
    } finally {
      fs.rmSync(own, { recursive: true, force: true });
    }
  });

  it('a version string that could escape the cache root is refused before the cache is touched', () => {
    // Returns before calling Node's API, so the test process is not switched over.
    expect(enableCompileCache(home, '../escape')).toBeNull();
    expect(enableCompileCache(home, 'a/b')).toBeNull();
  });

  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
    'a read-only home never breaks the call',
    () => {
      fs.chmodSync(path.join(home, '.node9'), 0o555);
      try {
        const v = run(['--version']);
        expect(v.status).toBe(0);
        expect(v.stdout.trim()).toBe(VERSION);
        const c = run(['check'], payload('Read', { file_path: path.join(home, 'a.txt') }));
        expect(c.status).toBe(0);
      } finally {
        fs.chmodSync(path.join(home, '.node9'), 0o755);
      }
    }
  );
});

describe('the hook bundle loads only what a hook needs', () => {
  it('dist/hook.js does not require the CLI-only modules', () => {
    const src = fs.readFileSync(path.join(DIST, 'hook.js'), 'utf-8');
    for (const mod of ['execa', '@inquirer/prompts', 'string-width', 'sqlite', 'mvdan-sh']) {
      expect(src, mod).not.toContain(`require("${mod}")`);
    }
  });

  it('a Read call never loads the shell parser; a Bash call does', () => {
    const probe = path.join(home, 'probe.cjs');
    const out = path.join(home, 'loaded.txt');
    fs.writeFileSync(
      probe,
      `process.on('exit', () => require('fs').writeFileSync(${JSON.stringify(out)}, ` +
        `Object.keys(require.cache).filter((k) => k.includes('mvdan-sh')).length > 0 ? 'yes' : 'no'));\n`
    );
    const opts = { NODE_OPTIONS: `--require ${probe}` };
    run(['check'], payload('Read', { file_path: path.join(home, 'a.txt') }), opts);
    expect(fs.readFileSync(out, 'utf-8')).toBe('no');
    run(['check'], payload('Bash', { command: 'ls -la | head -3' }), opts);
    expect(fs.readFileSync(out, 'utf-8')).toBe('yes');
  });
});
