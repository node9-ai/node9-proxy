// Integration: `node9 jail add/list/remove` grows the credential jail in place by
// materializing a `user-jail` shield from ~/.node9/jail-paths.json. Spawns
// dist/cli.js (file writes → integration, per CLAUDE.md). Requires `npm run build`.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function makeHome(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-jail-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  return h;
}

function run(home: string, args: string[]) {
  // No shell → `~/...` args are passed literally (not tilde-expanded).
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(),
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
    },
  });
}

const storePath = (h: string) => path.join(h, '.node9', 'jail-paths.json');
const jailShieldPath = (h: string) => path.join(h, '.node9', 'shields', 'user-jail.json');
const store = (h: string): { path: string; verdict: string }[] => {
  if (!fs.existsSync(storePath(h))) return [];
  return (JSON.parse(fs.readFileSync(storePath(h), 'utf8')).paths ?? []) as {
    path: string;
    verdict: string;
  }[];
};
const active = (h: string): string[] => {
  const p = path.join(h, '.node9', 'shields.json');
  if (!fs.existsSync(p)) return [];
  const raw = JSON.parse(fs.readFileSync(p, 'utf8')) as { active?: string[] } | string[];
  return Array.isArray(raw) ? raw : (raw.active ?? []);
};

describe('node9 jail', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
  });

  it('add: stores the path, builds + enables the user-jail shield, and gates (explain BLOCK)', () => {
    const h = makeHome();
    const r = run(h, ['jail', 'add', '~/.gmail-mcp']);
    expect(r.status).toBe(0);
    expect(store(h)).toEqual([{ path: '~/.gmail-mcp', verdict: 'block' }]);
    expect(fs.existsSync(jailShieldPath(h))).toBe(true);
    expect(active(h)).toContain('user-jail');
    const e = run(h, ['explain', 'bash', 'cat ~/.gmail-mcp/server.json']);
    expect(e.stdout + e.stderr).toMatch(/Decision: .*BLOCK/);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('add --review: stores review verdict and gates as REVIEW', () => {
    const h = makeHome();
    run(h, ['jail', 'add', '--review', '~/.mytokens']);
    expect(store(h)).toEqual([{ path: '~/.mytokens', verdict: 'review' }]);
    const e = run(h, ['explain', 'bash', 'cat ~/.mytokens/key']);
    expect(e.stdout + e.stderr).toMatch(/Decision: .*REVIEW/);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('add is idempotent / updates verdict (dedup by path)', () => {
    const h = makeHome();
    run(h, ['jail', 'add', '~/.foo']);
    run(h, ['jail', 'add', '--review', '~/.foo']);
    expect(store(h)).toEqual([{ path: '~/.foo', verdict: 'review' }]);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('remove of the last path disables + deletes the user-jail shield, and stops gating', () => {
    const h = makeHome();
    run(h, ['jail', 'add', '~/.gmail-mcp']);
    const rm = run(h, ['jail', 'remove', '~/.gmail-mcp']);
    expect(rm.status).toBe(0);
    expect(store(h)).toEqual([]);
    expect(fs.existsSync(jailShieldPath(h))).toBe(false);
    expect(active(h)).not.toContain('user-jail');
    const e = run(h, ['explain', 'bash', 'cat ~/.gmail-mcp/server.json']);
    expect(e.stdout + e.stderr).toMatch(/Decision: .*ALLOW/);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('remove keeps the shield when other paths remain', () => {
    const h = makeHome();
    run(h, ['jail', 'add', '~/.a']);
    run(h, ['jail', 'add', '~/.b']);
    run(h, ['jail', 'remove', '~/.a']);
    expect(store(h).map((p) => p.path)).toEqual(['~/.b']);
    expect(fs.existsSync(jailShieldPath(h))).toBe(true);
    expect(active(h)).toContain('user-jail');
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('remove of an unknown path exits non-zero', () => {
    const h = makeHome();
    const r = run(h, ['jail', 'remove', '~/.nope']);
    expect(r.status).toBe(1);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('list shows built-in coverage and user paths', () => {
    const h = makeHome();
    run(h, ['jail', 'add', '~/.gmail-mcp']);
    const r = run(h, ['jail', 'list']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Built-in/i);
    expect(r.stdout).toMatch(/\.ssh/);
    expect(r.stdout).toMatch(/~\/\.gmail-mcp/);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('rejects an over-broad path (~, /) that would produce no rule', () => {
    const h = makeHome();
    const r = run(h, ['jail', 'add', '~']);
    expect(r.status).toBe(1);
    expect(store(h)).toEqual([]); // nothing written
    expect(fs.existsSync(jailShieldPath(h))).toBe(false);
    fs.rmSync(h, { recursive: true, force: true });
  });
});
