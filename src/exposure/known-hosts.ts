// src/exposure/known-hosts.ts
// Hosts the project already talks to (fw#318 P3, design 5.3): the
// repository's own git remotes, and the default registry of each ecosystem
// the project uses (a package.json means npm). A send there after the
// session read outside content is logged, not held. On a git host the
// repository is compared, not the host: github.com holds the project's origin
// and every other repository too. Cached per process; the hook lives for one
// call.
import fs from 'fs';
import path from 'path';
import { readGitRemotes } from '../utils/git-remotes';

export interface KnownProjectHosts {
  /** `host:` destinations of every remote url plus the ecosystems' registries. */
  hosts: Set<string>;
  /** The repositories the remotes name, `host/owner/name`. */
  repos: Set<string>;
  /** Remote name -> its `host:` destinations, for `git push <name>`. */
  remotes: Map<string, string[]>;
}

// Manifest file -> the registry its ecosystem publishes to by default.
const ECOSYSTEMS: ReadonlyArray<readonly [manifest: string, registry: string]> = [
  ['package.json', 'host:registry.npmjs.org'],
  ['pyproject.toml', 'host:upload.pypi.org'],
  ['setup.py', 'host:upload.pypi.org'],
  ['Cargo.toml', 'host:crates.io'],
  ['Gemfile', 'host:rubygems.org'],
];

const cache = new Map<string, KnownProjectHosts>();

/** Walk up from `dir` to the nearest directory holding any manifest. */
function manifestRoot(dir: string): string | null {
  let cur = path.resolve(dir);
  for (let i = 0; i < 64; i++) {
    for (const [m] of ECOSYSTEMS) {
      try {
        if (fs.existsSync(path.join(cur, m))) return cur;
      } catch {
        /* unreadable: keep walking */
      }
    }
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
  return null;
}

export function knownProjectHosts(dir: string | undefined): KnownProjectHosts {
  const empty: KnownProjectHosts = { hosts: new Set(), repos: new Set(), remotes: new Map() };
  if (!dir) return empty;
  const key = path.resolve(dir);
  const hit = cache.get(key);
  if (hit) return hit;
  const out: KnownProjectHosts = { hosts: new Set(), repos: new Set(), remotes: new Map() };
  try {
    for (const r of readGitRemotes(key)) {
      out.remotes.set(r.name, r.hosts);
      for (const h of r.hosts) out.hosts.add(h);
      for (const repo of r.repos) out.repos.add(repo);
    }
    const root = manifestRoot(key);
    if (root !== null) {
      for (const [m, registry] of ECOSYSTEMS) {
        if (fs.existsSync(path.join(root, m))) out.hosts.add(registry);
      }
      // A gemspec next to no Gemfile still publishes to rubygems.
      try {
        if (fs.readdirSync(root).some((f) => f.endsWith('.gemspec')))
          out.hosts.add('host:rubygems.org');
      } catch {
        /* unreadable dir */
      }
    }
  } catch {
    /* never fail a hook over this */
  }
  cache.set(key, out);
  return out;
}

export function _resetKnownHostsCache(): void {
  cache.clear();
}
