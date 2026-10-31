// node9Firewall#415 item 4: the registries the user's own configuration names.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { configuredRegistryHosts, _resetRegistryCache } from '../supply-chain/registries';

let room: string;
let home: string;
let project: string;

beforeEach(() => {
  _resetRegistryCache();
  room = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-registries-'));
  home = path.join(room, 'home');
  project = path.join(room, 'work', 'app');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(project, { recursive: true });
});

afterEach(() => fs.rmSync(room, { recursive: true, force: true }));

describe('configuredRegistryHosts', () => {
  it('reads npm, pip and uv config files in home and the project and its parents', () => {
    fs.writeFileSync(path.join(home, '.npmrc'), 'registry=https://npm.corp.example.test/\n');
    fs.mkdirSync(path.join(home, '.config', 'pip'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.config', 'pip', 'pip.conf'),
      '[global]\nindex-url = https://pypi.corp.example.test/simple\n'
    );
    fs.writeFileSync(
      path.join(room, 'work', '.npmrc'),
      '@corp:registry=https://scoped.example.test/\n'
    );
    fs.writeFileSync(
      path.join(project, 'pyproject.toml'),
      '[[tool.uv.index]]\nname = "corp"\nurl = "https://uv.corp.example.test/simple"\n'
    );
    const hosts = configuredRegistryHosts(project, {}, home);
    expect([...hosts].sort()).toEqual([
      'npm.corp.example.test',
      'pypi.corp.example.test',
      'scoped.example.test',
      'uv.corp.example.test',
    ]);
  });

  it('reads the variables the package managers read', () => {
    const hosts = configuredRegistryHosts(
      project,
      {
        npm_config_registry: 'https://a.example.test/',
        PIP_EXTRA_INDEX_URL: 'https://b.example.test/s https://c.example.test/s',
      },
      home
    );
    expect([...hosts].sort()).toEqual(['a.example.test', 'b.example.test', 'c.example.test']);
  });

  it('the cached answer follows the environment (code review)', () => {
    expect(configuredRegistryHosts(project, {}, home).size).toBe(0);
    const hosts = configuredRegistryHosts(
      project,
      { npm_config_registry: 'https://a.example.test/' },
      home
    );
    expect([...hosts]).toEqual(['a.example.test']);
  });

  it('a commented line and a URL on an unrelated line do not count', () => {
    fs.writeFileSync(
      path.join(project, '.npmrc'),
      '# registry=https://old.example.test/\nhomepage https://docs.example.test\n'
    );
    expect(configuredRegistryHosts(project, {}, home).size).toBe(0);
  });

  // Release review: a project's own links are not registries. Counting the
  // `Source` line made gitlab.com "configured", so any GitLab project's
  // package registry passed.
  it("a project's [project.urls] links are not registries", () => {
    fs.writeFileSync(
      path.join(project, 'pyproject.toml'),
      '[project]\nname = "demo"\n\n[project.urls]\nSource = "https://gitlab.example.test/o/demo"\n' +
        'Documentation = "https://docs.example.test/index.html"\n'
    );
    fs.writeFileSync(
      path.join(project, 'Pipfile'),
      '[[source]]\nurl = "https://pipenv.corp.example.test/simple"\nname = "corp"\n'
    );
    expect([...configuredRegistryHosts(project, {}, home)]).toEqual(['pipenv.corp.example.test']);
  });

  it('pip multi-line extra-index-url, bunfig scopes and yarn berry', () => {
    fs.mkdirSync(path.join(home, '.config', 'pip'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.config', 'pip', 'pip.conf'),
      '[global]\nextra-index-url =\n    https://a.example.test/simple\n    https://b.example.test/simple\n' +
        'timeout = 60\n'
    );
    fs.writeFileSync(
      path.join(project, 'bunfig.toml'),
      '[install.scopes]\nmyorg = { token = "t", url = "https://bun.corp.example.test/" }\n'
    );
    fs.writeFileSync(
      path.join(project, '.yarnrc.yml'),
      'npmRegistryServer: "https://yarn.corp.example.test"\n'
    );
    expect([...configuredRegistryHosts(project, {}, home)].sort()).toEqual([
      'a.example.test',
      'b.example.test',
      'bun.corp.example.test',
      'yarn.corp.example.test',
    ]);
  });

  it('a relative working directory reads no project files', () => {
    fs.writeFileSync(path.join(project, '.npmrc'), 'registry=https://npm.corp.example.test/\n');
    expect(configuredRegistryHosts('work/app', {}, home).size).toBe(0);
  });
});
