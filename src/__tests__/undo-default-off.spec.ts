import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';

// `enableUndo` ships OFF.
//
// Why: the snapshot store is a per-project bare git repo with no size ceiling,
// and eviction removes the INDEX row without deleting the objects. On the
// founder's machine it reached 378G (352G of it orphaned `tmp_pack_*` from
// interrupted `git gc`) and took the disk to 100%. A security tool must not be
// the thing that fills a customer's disk, so the capture is off until the
// copy-store rewrite lands (doc/undo-v2-copy-store-design.md).
//
// Turning a default OFF is a silent behaviour change for every install that
// never set the field, so the second half of this corpus is about VISIBILITY:
// a user must be able to tell "disabled" from "nothing captured yet".

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function makeHome(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-undo-default-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  return h;
}

function runCli(home: string, args: string[]) {
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

const homes: string[] = [];
beforeEach(() => {
  expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
});
afterEach(() => {
  for (const h of homes.splice(0)) {
    try {
      fs.rmSync(h, { recursive: true, force: true });
    } catch {
      /* windows EBUSY */
    }
  }
});

describe('enableUndo default', () => {
  it('is OFF when the field is absent from config', async () => {
    // The real caller: getConfig() with no `settings.enableUndo` key at all,
    // which is what every fresh install has.
    const { DEFAULT_CONFIG } = await import('../config/index.js');
    expect(DEFAULT_CONFIG.settings.enableUndo).toBe(false);
  });

  it('an explicit true still wins — the default is a default, not a lock', async () => {
    const home = makeHome();
    homes.push(home);
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } })
    );
    const r = runCli(home, ['status']);
    expect(r.error).toBeUndefined();
    expect(r.stdout).toMatch(/Undo Engine/i);
  });
});

describe('a disabled undo is VISIBLE, not silent', () => {
  it('`node9 undo` says it is disabled rather than "no snapshots found"', () => {
    const home = makeHome();
    homes.push(home);
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: false } })
    );

    const r = runCli(home, ['undo', '--list']);
    expect(r.error).toBeUndefined();
    const out = `${r.stdout}${r.stderr}`;
    // The old message claimed nothing had been captured, which is a different
    // (and wrong) diagnosis — the user would go looking for a broken hook.
    expect(out).toMatch(/disabled/i);
    expect(out).toMatch(/enableUndo/);
  });

  it('`node9 status` reports the engine as off instead of omitting it', () => {
    const home = makeHome();
    homes.push(home);
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: false } })
    );

    const r = runCli(home, ['status']);
    expect(r.error).toBeUndefined();
    // Previously the whole line was omitted when off — indistinguishable from
    // a build that has no undo feature at all.
    expect(r.stdout).toMatch(/Undo Engine/i);
    expect(r.stdout).toMatch(/off|disabled/i);
  });
});
