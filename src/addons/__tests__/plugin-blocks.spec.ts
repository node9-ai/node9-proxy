// A plugin the workspace blocked is turned off in Claude Code, and put back
// when the block is lifted (node9Firewall#376 item 6).
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { applyPluginBlocks } from '../plugin-blocks';
import type { AddonPolicy } from '../policy';

const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});

function home(enabledPlugins?: Record<string, boolean>): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-plugin-blocks-'));
  homes.push(h);
  const plugins: Record<string, unknown> = {};
  for (const name of ['lint', 'docs']) {
    const dir = path.join(h, '.claude', 'plugins', 'cache', 'm', name, '1.0.0');
    fs.mkdirSync(dir, { recursive: true });
    plugins[`${name}@m`] = [{ version: '1.0.0', installPath: dir }];
  }
  fs.writeFileSync(
    path.join(h, '.claude', 'plugins', 'installed_plugins.json'),
    JSON.stringify({ plugins })
  );
  fs.writeFileSync(
    path.join(h, '.claude', 'settings.json'),
    JSON.stringify({
      model: 'opus',
      hooks: { PreToolUse: [] },
      ...(enabledPlugins ? { enabledPlugins } : {}),
    })
  );
  return h;
}

const settings = (h: string) =>
  JSON.parse(fs.readFileSync(path.join(h, '.claude', 'settings.json'), 'utf8')) as {
    model?: string;
    hooks?: unknown;
    enabledPlugins?: Record<string, boolean>;
  };

const list = (plugins: AddonPolicy['plugins']): AddonPolicy => ({
  unapproved: 'block',
  mcp: {},
  skills: {},
  plugins,
});

describe('applyPluginBlocks', () => {
  it('turns off a blocked plugin and leaves the rest of the settings as they were', () => {
    const h = home({ 'lint@m': true, 'docs@m': true });
    const r = applyPluginBlocks(list({ 'lint@m': { decision: 'blocked' } }), h);
    expect(r.turnedOff).toEqual(['lint@m']);
    const s = settings(h);
    expect(s.enabledPlugins).toEqual({ 'lint@m': false, 'docs@m': true });
    expect(s.model).toBe('opus');
    expect(s.hooks).toEqual({ PreToolUse: [] });
  });

  it('never turns off a plugin nobody decided on, even under the block rule', () => {
    const h = home({ 'docs@m': true });
    expect(applyPluginBlocks(list({}), h)).toEqual({ turnedOff: [], restored: [] });
    expect(settings(h).enabledPlugins).toEqual({ 'docs@m': true });
  });

  it('puts back exactly what was there when the block is lifted or the list goes', () => {
    const h = home({ 'docs@m': true }); // lint@m not set at all
    applyPluginBlocks(
      list({ 'lint@m': { decision: 'blocked' }, 'docs@m': { decision: 'blocked' } }),
      h
    );
    expect(settings(h).enabledPlugins).toEqual({ 'docs@m': false, 'lint@m': false });
    // The block on docs is lifted: back to true. Lint still blocked.
    applyPluginBlocks(list({ 'lint@m': { decision: 'blocked' } }), h);
    expect(settings(h).enabledPlugins).toEqual({ 'docs@m': true, 'lint@m': false });
    // No list any more (a downgrade): lint goes back to unset.
    expect(applyPluginBlocks(undefined, h).restored).toEqual(['lint@m']);
    expect(settings(h).enabledPlugins).toEqual({ 'docs@m': true });
  });

  it("keeps the person's own change: a plugin they turned back on stays on", () => {
    const h = home({ 'lint@m': true });
    applyPluginBlocks(list({ 'lint@m': { decision: 'blocked' } }), h);
    // They switch it on by hand, then the block is lifted.
    const s = settings(h);
    s.enabledPlugins!['lint@m'] = true;
    fs.writeFileSync(path.join(h, '.claude', 'settings.json'), JSON.stringify(s));
    applyPluginBlocks(list({}), h);
    expect(settings(h).enabledPlugins).toEqual({ 'lint@m': true });
  });

  it('never rewrites a settings file it cannot read', () => {
    const h = home();
    fs.writeFileSync(path.join(h, '.claude', 'settings.json'), '{ not json');
    applyPluginBlocks(list({ 'lint@m': { decision: 'blocked' } }), h);
    expect(fs.readFileSync(path.join(h, '.claude', 'settings.json'), 'utf8')).toBe('{ not json');
  });

  it('leaves a plugin that is not installed alone', () => {
    const h = home({});
    expect(applyPluginBlocks(list({ 'other@m': { decision: 'blocked' } }), h).turnedOff).toEqual(
      []
    );
  });

  it.skipIf(process.platform === 'win32')('keeps the settings file mode', () => {
    const h = home({ 'lint@m': true });
    fs.chmodSync(path.join(h, '.claude', 'settings.json'), 0o600);
    applyPluginBlocks(list({ 'lint@m': { decision: 'blocked' } }), h);
    expect(fs.statSync(path.join(h, '.claude', 'settings.json')).mode & 0o777).toBe(0o600);
  });
});
