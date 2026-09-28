import { afterEach, describe, expect, it } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { pathToFileURL } from 'url';
const root = path.resolve(__dirname, '../..');
const homes: string[] = [];
function run(source: string, managed = false) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-setup-effects-'));
  homes.push(home);
  fs.mkdirSync(path.join(home, '.node9'));
  const original = {
    custom: 42,
    settings: { autoStartDaemon: false },
    policy: {
      dlp: { enabled: true, pii: 'block', scanIgnoredTools: false },
      egress: { enabled: false, allow: ['example.com'], deny: ['denied.example'] },
    },
  };
  fs.writeFileSync(path.join(home, '.node9/config.json'), JSON.stringify(original));
  fs.writeFileSync(
    path.join(home, '.node9/shields.json'),
    JSON.stringify({ active: ['postgres'] })
  );
  if (managed)
    fs.writeFileSync(
      path.join(home, '.node9/credentials.json'),
      JSON.stringify({ default: { apiKey: 'test-machine-key' } })
    );
  const script = path.join(home, 'exercise.mts');
  fs.writeFileSync(
    script,
    // A file URL, not a path: the ESM loader reads a Windows "D:\..." as a URL scheme.
    `import { applyChanges } from ${JSON.stringify(pathToFileURL(path.join(root, 'src/cli/local-setup.ts')).href)};\n${source}`
  );
  const r = spawnSync(
    process.execPath,
    [path.join(root, 'node_modules/tsx/dist/cli.mjs'), script],
    {
      cwd: home,
      env: {
        PATH: path.dirname(process.execPath),
        HOME: home,
        USERPROFILE: home,
        NODE9_TESTING: '1',
        NODE9_NO_AUTO_DAEMON: '1',
      },
      encoding: 'utf8',
      timeout: 15000,
    }
  );
  expect(r.error).toBeUndefined();
  expect(r.status, r.stderr).toBe(0);
  return { home, original, output: r.stdout };
}
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});
describe('setup changes with isolated HOME', () => {
  it('changes selected fields and preserves unrelated rules, options, and shields', () => {
    const { home } = run(`
      console.log(JSON.stringify(await applyChanges([
        { key: 'shields', from: 'off', to: true },
        { key: 'dlp', from: 'on', to: false },
        { key: 'egress', from: 'off', to: true },
      ])));
    `);
    const config = JSON.parse(fs.readFileSync(path.join(home, '.node9/config.json'), 'utf8'));
    expect(config.custom).toBe(42);
    expect(config.policy.dlp).toMatchObject({
      enabled: false,
      pii: 'off',
      scanIgnoredTools: false,
    });
    expect(config.policy.egress).toMatchObject({
      enabled: true,
      mode: 'review',
      allow: ['example.com'],
      deny: ['denied.example'],
    });
    expect(
      JSON.parse(fs.readFileSync(path.join(home, '.node9/shields.json'), 'utf8')).active
    ).toEqual(['postgres', 'bash-safe', 'filesystem', 'project-jail']);
  });
  it('removes only recommended shields and can restore DLP while disabling egress', () => {
    const { home } = run(`
      await applyChanges([{ key: 'shields', from: 'off', to: true }]);
      await applyChanges([{ key: 'shields', from: 'on', to: false }, { key: 'dlp', from: 'off', to: true }, { key: 'egress', from: 'on', to: false }]);
    `);
    expect(
      JSON.parse(fs.readFileSync(path.join(home, '.node9/shields.json'), 'utf8')).active
    ).toEqual(['postgres']);
    const config = JSON.parse(fs.readFileSync(path.join(home, '.node9/config.json'), 'utf8'));
    expect(config.policy.dlp.enabled).toBe(true);
    expect(config.policy.dlp.pii).toBe('block');
    expect(config.policy.egress.enabled).toBe(false);
  });
  it('does not write policy on a managed machine even if invoked directly', () => {
    const { home, original, output } = run(
      `console.log(JSON.stringify(await applyChanges([
      { key: 'dlp', from: 'on', to: false }, { key: 'egress', from: 'off', to: true },
    ])));`,
      true
    );
    expect(output).toContain('managed by your workspace');
    expect(fs.readFileSync(path.join(home, '.node9/config.json'), 'utf8')).toBe(
      JSON.stringify(original)
    );
  });
});
