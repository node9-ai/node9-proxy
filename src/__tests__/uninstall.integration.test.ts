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
  // opencode's config dir resolves under $XDG_CONFIG_HOME when set (CI runners
  // set it); clear it so the shim resolves under HOME/.config, matching
  // opencodeShim() below (#186).
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NO_COLOR: '1',
  };
  delete env.XDG_CONFIG_HOME;
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(),
    env,
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

  it('uninstall reports an accurate leftover-scan when nothing remains', () => {
    const h = makeHome();
    const r = run(h, ['uninstall']);
    expect(r.status).toBe(0);
    // Scoped claim: verifies hooks + plugin shims (the registry agents), not a
    // blanket "nothing left behind" that would over-claim the 4 non-registry agents.
    expect(r.stdout).toMatch(/no node9 hooks or plugin shims remain/i);
    fs.rmSync(h, { recursive: true, force: true });
  });

  // Full-flow regression for the statusLine bug: uninstall must remove node9's
  // hooks but NEVER delete a statusLine the user set (e.g. ccstatusline). #186.
  it('uninstall removes node9 hooks but preserves a user statusLine', () => {
    const h = makeHome();
    const settingsPath = path.join(h, '.claude', 'settings.json');
    const userStatusLine = { type: 'command', command: 'npx -y ccstatusline@latest' };
    write(
      settingsPath,
      JSON.stringify({
        hooks: {
          PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'node9 log' }] }],
        },
        statusLine: userStatusLine,
      })
    );
    const r = run(h, ['uninstall']);
    expect(r.status).toBe(0);
    const after = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    expect(after.statusLine).toEqual(userStatusLine); // user's statusLine preserved
    expect(JSON.stringify(after.hooks ?? {})).not.toContain('node9'); // node9 hooks removed
    fs.rmSync(h, { recursive: true, force: true });
  });

  it("uninstall removes node9's own HUD from statusLine", () => {
    const h = makeHome();
    const settingsPath = path.join(h, '.claude', 'settings.json');
    write(settingsPath, JSON.stringify({ statusLine: { type: 'command', command: 'node9 hud' } }));
    const r = run(h, ['uninstall']);
    expect(r.status).toBe(0);
    const after = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    expect(after.statusLine).toBeUndefined(); // node9 HUD removed
    fs.rmSync(h, { recursive: true, force: true });
  });
});
