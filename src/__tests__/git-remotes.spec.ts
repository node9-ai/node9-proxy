// fw#318 P3, design 5.3: the repository's own remotes and the ecosystem
// registries are known hosts for a send after the session read outside
// content. Read from .git/config and the manifests, never by running git.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readGitRemotes, gitRemoteHost, _resetGitRemotesCache } from '../utils/git-remotes';
import { knownProjectHosts, _resetKnownHostsCache } from '../exposure/known-hosts';

let root: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-remotes-'));
  _resetGitRemotesCache();
  _resetKnownHostsCache();
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

const CONFIG = `[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://github.com/acme/app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[remote "deploy"]
\turl = git@git.corp.example:ops/app.git
\tpushurl = ssh://git@mirror.corp.example:2222/ops/app.git
[branch "main"]
\tremote = origin
`;

describe('gitRemoteHost', () => {
  it('reads https, ssh:// and scp-like urls; a path has no host', () => {
    expect(gitRemoteHost('https://github.com/acme/app.git')).toBe('github.com');
    expect(gitRemoteHost('ssh://git@mirror.corp.example:2222/ops/app.git')).toBe(
      'mirror.corp.example'
    );
    expect(gitRemoteHost('git@git.corp.example:ops/app.git')).toBe('git.corp.example');
    expect(gitRemoteHost('/srv/git/app.git')).toBeNull();
    expect(gitRemoteHost('../other')).toBeNull();
  });
});

describe('readGitRemotes', () => {
  it('parses every remote with url and pushurl, from a subdirectory', () => {
    fs.mkdirSync(path.join(root, '.git'));
    fs.writeFileSync(path.join(root, '.git', 'config'), CONFIG);
    fs.mkdirSync(path.join(root, 'src', 'deep'), { recursive: true });
    const remotes = readGitRemotes(path.join(root, 'src', 'deep'));
    expect(remotes.map((r) => r.name)).toEqual(['origin', 'deploy']);
    expect(remotes[0].hosts).toEqual(['host:github.com']);
    expect(remotes[1].hosts).toEqual(['host:git.corp.example', 'host:mirror.corp.example']);
  });

  it('follows a worktree pointer and commondir', () => {
    const main = path.join(root, 'main');
    fs.mkdirSync(path.join(main, '.git', 'worktrees', 'wt'), { recursive: true });
    fs.writeFileSync(path.join(main, '.git', 'config'), CONFIG);
    fs.writeFileSync(path.join(main, '.git', 'worktrees', 'wt', 'commondir'), '../..\n');
    const wt = path.join(root, 'wt');
    fs.mkdirSync(wt);
    fs.writeFileSync(
      path.join(wt, '.git'),
      `gitdir: ${path.join(main, '.git', 'worktrees', 'wt')}\n`
    );
    expect(readGitRemotes(wt).map((r) => r.name)).toEqual(['origin', 'deploy']);
  });

  it('no repository, no remotes; never throws', () => {
    expect(readGitRemotes(root)).toEqual([]);
    expect(readGitRemotes(undefined)).toEqual([]);
    expect(readGitRemotes(path.join(root, 'missing'))).toEqual([]);
  });
});

describe('knownProjectHosts', () => {
  it('remotes plus the registries of the manifests present', () => {
    fs.mkdirSync(path.join(root, '.git'));
    fs.writeFileSync(path.join(root, '.git', 'config'), CONFIG);
    fs.writeFileSync(path.join(root, 'package.json'), '{}');
    fs.writeFileSync(path.join(root, 'Cargo.toml'), '');
    const k = knownProjectHosts(root);
    expect([...k.hosts].sort()).toEqual(
      [
        'host:github.com',
        'host:git.corp.example',
        'host:mirror.corp.example',
        'host:registry.npmjs.org',
        'host:crates.io',
      ].sort()
    );
    expect(k.remotes.get('origin')).toEqual(['host:github.com']);
  });

  it('a project with no manifest and no remote knows nothing', () => {
    const k = knownProjectHosts(root);
    expect(k.hosts.size).toBe(0);
    expect(k.remotes.size).toBe(0);
  });
});
