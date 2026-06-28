// Integration: `node9 shield create` writes a valid user shield, guards against
// built-in collisions / overwrites / empty shields, optionally enables, and the
// created shield actually gates (proven via `node9 explain`). Spawns dist/cli.js
// (file writes → integration, per CLAUDE.md). Requires `npm run build`.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { validateShieldDefinition } from '@node9/policy-engine';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function makeHome(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-shieldcreate-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  return h;
}

function run(home: string, args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(), // no project node9.config.json
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

const shieldPath = (h: string, name: string) => path.join(h, '.node9', 'shields', `${name}.json`);
const activeList = (h: string): string[] => {
  const p = path.join(h, '.node9', 'shields.json');
  if (!fs.existsSync(p)) return [];
  const raw = JSON.parse(fs.readFileSync(p, 'utf-8')) as { active?: string[] } | string[];
  return Array.isArray(raw) ? raw : (raw.active ?? []);
};

describe('node9 shield create', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
  });

  it('writes a valid shield from inline flags (not enabled by default)', () => {
    const h = makeHome();
    const r = run(h, [
      'shield',
      'create',
      'my-gmail',
      '--block-path',
      '~/.gmail-mcp',
      '--review-tool',
      'send_email',
      '--desc',
      'Protect Gmail MCP',
    ]);
    expect(r.status).toBe(0);
    const file = shieldPath(h, 'my-gmail');
    expect(fs.existsSync(file)).toBe(true);
    const def = JSON.parse(fs.readFileSync(file, 'utf-8'));
    expect('ok' in validateShieldDefinition(def)).toBe(true);
    expect(def.smartRules).toHaveLength(3); // 2 path rules + 1 tool rule
    expect(activeList(h)).not.toContain('my-gmail'); // no --enable
    expect(r.stdout).toMatch(/created/i);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('--enable activates the shield in shields.json', () => {
    const h = makeHome();
    const r = run(h, ['shield', 'create', 'jailit', '--block-path', '~/.secret', '--enable']);
    expect(r.status).toBe(0);
    expect(activeList(h)).toContain('jailit');
    expect(r.stdout).toMatch(/active now/i);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('refuses to shadow a built-in shield name', () => {
    const h = makeHome();
    const r = run(h, ['shield', 'create', 'postgres', '--block-tool', 'psql']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/built-in/i);
    expect(fs.existsSync(shieldPath(h, 'postgres'))).toBe(false);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('refuses to overwrite an existing shield without --overwrite, allows with it', () => {
    const h = makeHome();
    run(h, ['shield', 'create', 'dup', '--block-tool', 'rm']);
    const again = run(h, ['shield', 'create', 'dup', '--block-tool', 'curl']);
    expect(again.status).toBe(1);
    expect(again.stderr).toMatch(/already exists/i);
    const forced = run(h, ['shield', 'create', 'dup', '--block-tool', 'curl', '--overwrite']);
    expect(forced.status).toBe(0);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('refuses a shield with no rules', () => {
    const h = makeHome();
    const r = run(h, ['shield', 'create', 'empty']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/no rules/i);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('the created+enabled shield actually gates (explain shows BLOCK via the new rule)', () => {
    const h = makeHome();
    run(h, ['shield', 'create', 'gmail-jail', '--block-path', '~/.gmail-mcp', '--enable']);
    // Use a non-sensitive filename so the built-in credential detector (a Layer-1
    // gate that runs before user rules) doesn't catch it first — this isolates
    // the verdict to OUR created shield rule.
    const e = run(h, ['explain', 'bash', 'cat ~/.gmail-mcp/server.json']);
    const out = e.stdout + e.stderr;
    expect(out).toMatch(/Decision: .*BLOCK/);
    expect(out).toMatch(/gmail-mcp/); // attributed to our shield's rule
    fs.rmSync(h, { recursive: true, force: true });
  });
});
