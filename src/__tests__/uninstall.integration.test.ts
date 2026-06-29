// Integration: `node9 uninstall` must remove EVERY agent's hooks/shims, not just
// the 7 that were hardcoded. Regression for the churn bug (#186): Opencode + Pi
// plugin shims were left behind. Spawns dist/cli.js (file writes → integration,
// per CLAUDE.md). Requires `npm run build`.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function makeHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'node9-uninstall-'));
}
function write(file: string, content = '// node9 shim\n'): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}
function run(home: string, args: string[]) {
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

// The plugin-shim residue paths (from the agent-wiring registry).
const opencodeShim = (h: string) => path.join(h, '.config', 'opencode', 'plugins', 'node9.js');
const piShim = (h: string) => path.join(h, '.pi', 'agent', 'extensions', 'node9.js');

describe('node9 uninstall — removes plugin-shim agents (Opencode + Pi)', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
  });

  it('uninstall removes the Opencode and Pi node9 shims', () => {
    const h = makeHome();
    write(opencodeShim(h));
    write(piShim(h));
    const r = run(h, ['uninstall']);
    expect(r.status).toBe(0);
    expect(fs.existsSync(opencodeShim(h))).toBe(false);
    expect(fs.existsSync(piShim(h))).toBe(false);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('removefrom opencode / pi removes their shim (per-agent path)', () => {
    const h = makeHome();
    write(opencodeShim(h));
    write(piShim(h));
    expect(run(h, ['removefrom', 'opencode']).status).toBe(0);
    expect(fs.existsSync(opencodeShim(h))).toBe(false);
    expect(run(h, ['removefrom', 'pi']).status).toBe(0);
    expect(fs.existsSync(piShim(h))).toBe(false);
    fs.rmSync(h, { recursive: true, force: true });
  });

  it('uninstall reports a clean leftover-scan when nothing remains', () => {
    const h = makeHome();
    const r = run(h, ['uninstall']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/nothing left behind/i);
    fs.rmSync(h, { recursive: true, force: true });
  });
});
