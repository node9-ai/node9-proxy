/**
 * Integration: the same-change suppression rule through the REAL CLI (`dist/cli.js`), in the
 * DEFAULT gate. A pull request that adds a finding and its `.node9-ignore.json` entry in one
 * commit must fail `scan-repo --base <base>` exactly as it would without the suppression.
 *
 * Requires `npm run build` (the `pretest` script does it). Uses a throwaway git repository.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const UNPINNED = (servers: string[]) =>
  JSON.stringify({
    mcpServers: Object.fromEntries(
      servers.map((s) => [s, { command: 'npx', args: ['-y', `@acme/${s}-mcp`] }])
    ),
  });
const ENTRY = (locator: string) =>
  JSON.stringify([
    { rule: 'CI-3.mcp-unpinned', file: '.mcp.json', locator, reason: 'accepted; tracked in #412' },
  ]);

let root = '';
let base = '';
const git = (...a: string[]) =>
  execFileSync('git', ['-C', root, ...a], { stdio: ['ignore', 'pipe', 'ignore'] })
    .toString()
    .trim();
const scan = (...extra: string[]) =>
  spawnSync(process.execPath, [CLI, 'scan-repo', root, '--json', ...extra], {
    encoding: 'utf8',
    env: { ...process.env, NODE9_TESTING: '1' },
    timeout: 60_000,
  });

beforeAll(() => {
  expect(fs.existsSync(CLI), 'dist/cli.js missing — run npm run build').toBe(true);
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-suppress-int-'));
  git('init', '-q');
  git('config', 'user.email', 't@e.test');
  git('config', 'user.name', 't');
  fs.writeFileSync(path.join(root, '.mcp.json'), UNPINNED(['search']));
  git('add', '-A');
  git('commit', '-qm', 'base: one unpinned server, not suppressed');
  base = git('rev-parse', 'HEAD');
});

afterAll(() => {
  if (root) fs.rmSync(root, { recursive: true, force: true });
});

describe('scan-repo --base: a suppression added in the same change does not open the default gate', () => {
  it('attack: a new finding and its suppression in one commit → exit non-zero, worst = medium', () => {
    git('checkout', '-q', '-B', 'attack', base);
    fs.writeFileSync(path.join(root, '.mcp.json'), UNPINNED(['search', 'evil']));
    fs.writeFileSync(path.join(root, '.node9-ignore.json'), ENTRY('evil'));
    git('add', '-A');
    git('commit', '-qm', 'add a server and silence it');

    const r = scan('--base', base);
    expect(r.error).toBeUndefined();
    expect(r.status).not.toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.worst).toBe('medium');
    const evil = out.findings.find((f: { locator?: string }) => f.locator === 'evil');
    expect(evil.suppressed).toBeUndefined();
    expect(out.diff.worstAll).toBe('medium');
  });

  it('legitimate: a commit that only suppresses the pre-existing finding → honoured', () => {
    git('checkout', '-q', '-B', 'accept', base);
    fs.writeFileSync(path.join(root, '.node9-ignore.json'), ENTRY('search'));
    git('add', '-A');
    git('commit', '-qm', 'accept the known server');

    const r = scan('--base', base);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.worst).toBeNull();
    expect(out.suppressedCount).toBe(1);
  });

  it('base unreadable: no suppression is honoured, the gate stays strict', () => {
    git('checkout', '-q', 'accept');
    const r = scan('--base', 'does-not-exist');
    expect(r.error).toBeUndefined();
    expect(r.status).not.toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.worst).toBe('medium');
    expect(out.diff.base).toBe('did-not-run');
  });

  it('no --base (a local run): suppressions apply as written', () => {
    git('checkout', '-q', 'accept');
    const r = scan();
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout).worst).toBeNull();
  });
});
