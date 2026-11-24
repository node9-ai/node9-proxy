import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { collectAddons, findSkillDirs } from '../collect';

const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});

function home(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-addons-'));
  homes.push(h);
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  return h;
}

function skill(dir: string, md: string, extra: Record<string, string> = {}): void {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'SKILL.md'), md);
  for (const [rel, text] of Object.entries(extra)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  }
}

const SECRET = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
/** A shape the DLP scanner recognises (a fake GitHub token fails its checksum). */
const STRIPE = 'sk_live_' + 'Z9y8X7w6V5u4T3s2R1q0P9o8';

describe('collectAddons: skills', () => {
  it('reports user skills by agent, with name, hash, grants and source, and no text', () => {
    const h = home();
    skill(
      path.join(h, '.claude', 'skills', 'deploy'),
      `---\nname: render-deploy\nallowed-tools: Bash(git push:*) Read\n---\nUse token ${SECRET}.\n`
    );
    skill(path.join(h, '.claude', 'skills', 'synced', 'bucket-1', 'pdf'), '# pdf\n');
    skill(path.join(h, '.codex', 'skills', '.system', 'imagegen'), '# imagegen\n');
    skill(path.join(h, '.agents', 'skills', 'shared-one'), '# shared\n');

    const r = collectAddons(h, {});
    const byName = Object.fromEntries(r.skills.map((s) => [s.name, s]));
    expect(Object.keys(byName).sort()).toEqual(['imagegen', 'pdf', 'render-deploy', 'shared-one']);
    expect(byName['render-deploy']).toMatchObject({ agent: 'claude', scope: 'user', fileCount: 1 });
    expect(byName['render-deploy'].grants).toEqual(['Bash(git push:*)', 'Read']);
    expect(byName['render-deploy'].hash).toMatch(/^[0-9a-f]{64}$/);
    expect(byName.pdf.source).toBe('synced');
    expect(byName.imagegen).toMatchObject({ agent: 'codex', source: 'built-in' });
    expect(byName['shared-one'].agent).toBe('shared');

    const wire = JSON.stringify(r);
    expect(wire).not.toContain(SECRET);
    expect(wire).not.toContain(h);
  });

  it('keeps the tool name of a grant that carries a credential, not the credential', () => {
    const h = home();
    skill(
      path.join(h, '.claude', 'skills', 'api'),
      `---\nname: api\nallowed-tools: Read, Bash(curl -u ${STRIPE}: https://api.stripe.com:*)\n---\n`
    );
    const [s] = collectAddons(h, {}).skills;
    expect(s.grants).toEqual(['Read', 'Bash(redacted)']);
    expect(JSON.stringify(s)).not.toContain(STRIPE);
  });

  it('carries rule ids for withdrawn vendor guidance found in a supporting file', () => {
    const h = home();
    skill(path.join(h, '.claude', 'skills', 'render'), '---\nname: render-deploy\n---\nDeploy.\n', {
      'references/service-types.md': 'Private services live at my-svc.render-internal.com.\n',
    });
    const [s] = collectAddons(h, {}).skills;
    expect(s.findings.map((f) => f.rule)).toContain('CI-6.withdrawn-guidance');
    expect(JSON.stringify(s)).not.toContain('render-internal');
  });

  it('gives two copies with different content different hashes', () => {
    const a = home();
    const b = home();
    skill(path.join(a, '.claude', 'skills', 'x'), '---\nname: x\n---\nv1\n');
    skill(path.join(b, '.claude', 'skills', 'x'), '---\nname: x\n---\nv2\n');
    expect(collectAddons(a, {}).skills[0].hash).not.toBe(collectAddons(b, {}).skills[0].hash);
  });

  it('does not follow a symlinked skill folder', () => {
    const h = home();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-outside-'));
    homes.push(outside);
    skill(path.join(outside, 'evil'), '# evil\n');
    fs.mkdirSync(path.join(h, '.claude', 'skills'), { recursive: true });
    fs.symlinkSync(path.join(outside, 'evil'), path.join(h, '.claude', 'skills', 'evil'));
    expect(collectAddons(h, {}).skills).toEqual([]);
  });

  it('does not read a SKILL.md that is a symlink or a FIFO', () => {
    const h = home();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-outside-'));
    homes.push(outside);
    fs.writeFileSync(path.join(outside, 'SKILL.md'), '---\nname: leaked-name\n---\n');
    const linked = path.join(h, '.claude', 'skills', 'linked');
    fs.mkdirSync(linked, { recursive: true });
    fs.symlinkSync(path.join(outside, 'SKILL.md'), path.join(linked, 'SKILL.md'));
    if (process.platform !== 'win32') {
      const fifoDir = path.join(h, '.claude', 'skills', 'fifo');
      fs.mkdirSync(fifoDir, { recursive: true });
      // A FIFO with no writer would block a plain open forever.
      const r = spawnSync('mkfifo', [path.join(fifoDir, 'SKILL.md')]);
      expect(r.status).toBe(0);
    }
    const names = collectAddons(h, {}).skills.map((s) => s.name);
    expect(names).not.toContain('leaked-name');
  });

  it('reports project skills from folders in the audit log, without the path', () => {
    const h = home();
    const project = path.join(h, 'work', 'client-acme');
    skill(path.join(project, '.claude', 'skills', 'release'), '---\nname: release\n---\n');
    fs.writeFileSync(
      path.join(h, '.node9', 'audit.log'),
      JSON.stringify({
        ts: '2026-11-23T10:00:00Z',
        tool: 'Bash',
        argsPreview: 'ls',
        workingDir: project,
      }) + '\n'
    );
    const r = collectAddons(h, {});
    expect(r.skills).toHaveLength(1);
    expect(r.skills[0]).toMatchObject({ name: 'release', scope: 'project', agent: 'claude' });
    expect(JSON.stringify(r)).not.toContain('client-acme');
  });

  it('stops at the cap and says so', () => {
    const h = home();
    for (let i = 0; i < 205; i++) skill(path.join(h, '.claude', 'skills', `s${i}`), '# s\n');
    const r = collectAddons(h, {});
    expect(r.skills).toHaveLength(200);
    expect(r.capped).toBe(true);
  });

  it('findSkillDirs does not look for skills inside a skill', () => {
    const h = home();
    skill(path.join(h, 'root', 'outer'), '# outer\n', { 'inner/SKILL.md': '# inner\n' });
    expect(findSkillDirs(path.join(h, 'root'))).toEqual([path.join(h, 'root', 'outer')]);
  });
});

describe('collectAddons: plugins', () => {
  it('reports installed plugins only, not the marketplace catalog', () => {
    const h = home();
    const plugins = path.join(h, '.claude', 'plugins');
    // The marketplace clone holds every plugin, installed or not.
    skill(
      path.join(plugins, 'marketplaces', 'official', 'plugins', 'not-installed', 'skills', 'nope'),
      '# nope\n'
    );
    const installPath = path.join(plugins, 'cache', 'official', 'reviewer', '1.2.0');
    skill(path.join(installPath, 'skills', 'review'), '---\nname: review\n---\n');
    fs.writeFileSync(
      path.join(plugins, 'installed_plugins.json'),
      JSON.stringify({
        version: 2,
        plugins: {
          'reviewer@official': [{ scope: 'user', installPath, version: '1.2.0' }],
          'elsewhere@official': [{ installPath: '/etc', version: '9' }],
        },
      })
    );
    fs.writeFileSync(
      path.join(h, '.claude', 'settings.json'),
      JSON.stringify({ enabledPlugins: { 'reviewer@official': true } })
    );

    const r = collectAddons(h, {});
    expect(r.plugins).toEqual([
      expect.objectContaining({
        name: 'reviewer',
        marketplace: 'official',
        version: '1.2.0',
        enabled: true,
      }),
      { name: 'elsewhere', marketplace: 'official', version: '9' },
    ]);
    expect(r.plugins[0].hash).toMatch(/^[0-9a-f]{64}$/);
    expect(r.skills.map((s) => [s.name, s.scope, s.source])).toEqual([
      ['review', 'plugin', 'reviewer@official'],
    ]);
  });

  it('accepts the map-of-object shape and ignores a malformed file', () => {
    const h = home();
    const plugins = path.join(h, '.claude', 'plugins');
    fs.mkdirSync(plugins, { recursive: true });
    fs.writeFileSync(
      path.join(plugins, 'installed_plugins.json'),
      JSON.stringify({ version: 1, plugins: { 'one@m': { version: '1' } } })
    );
    expect(collectAddons(h, {}).plugins).toEqual([{ name: 'one', marketplace: 'm', version: '1' }]);
    fs.writeFileSync(path.join(plugins, 'installed_plugins.json'), '{not json');
    expect(collectAddons(h, {}).plugins).toEqual([]);
  });
});

describe('collectAddons: MCP servers', () => {
  it('names each server by identity, merges agents, and keeps arguments and env values off the wire', () => {
    const h = home();
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({
        mcpServers: {
          db: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-postgres', 'postgres://u:hunter2@db/prod'],
            env: { PGPASSWORD: 'hunter2' },
          },
          wrapped: {
            command: 'node9',
            args: ['mcp-gateway', '--config-name', 'wrapped', '--upstream', 'uvx mcp-server-fetch'],
          },
          remote: { type: 'http', url: 'https://mcp.example.com/mcp?key=hunter2' },
        },
      })
    );
    const r = collectAddons(h, {});
    const byName = Object.fromEntries(r.mcp.map((m) => [m.name, m]));
    expect(byName.db).toMatchObject({
      identity: 'npm:@modelcontextprotocol/server-postgres',
      state: 'outside',
      agents: ['claude'],
    });
    expect(byName.wrapped).toMatchObject({ identity: 'pypi:mcp-server-fetch', state: 'governed' });
    expect(byName.wrapped.serverKey).toMatch(/^[0-9a-f]{16}$/);
    expect(byName.remote).toMatchObject({ identity: 'url:mcp.example.com', state: 'remote' });
    expect(JSON.stringify(r)).not.toContain('hunter2');
  });
});
