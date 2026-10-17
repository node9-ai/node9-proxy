// src/utils/git-remotes.ts
// The repository's own remotes, read from .git/config without running git
// (fw#318 P3, design 5.3). A `git push origin` after the session read outside
// content goes to a host the project already talks to: known, logged, not
// held. Worktrees are followed through `.git` pointer files and `commondir`,
// the same walk ci-check uses for the GitHub owner. Never throws; a missing
// or unreadable config is an empty list.
import fs from 'fs';
import path from 'path';
import { gitRepoPath } from '@node9/policy-engine';

export interface GitRemote {
  name: string;
  urls: string[];
  /** Lower-cased hosts of the urls, `host:` prefixed as the exposure gate compares them. */
  hosts: string[];
  /** The repositories the urls name, `host/owner/name` (gitRepoPath). */
  repos: string[];
}

function readSmallFile(p: string, max: number): string | null {
  let fd: number | undefined;
  try {
    fd = fs.openSync(p, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > max) return null;
    const buf = Buffer.alloc(st.size);
    const n = fs.readSync(fd, buf, 0, st.size, 0);
    return buf.subarray(0, n).toString('utf8');
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** The host of a git remote url: https, ssh://, scp-like `git@host:path`, or none (a path). */
export function gitRemoteHost(url: string): string | null {
  const u = url.trim();
  if (!u) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) {
    try {
      const h = new URL(u).hostname.toLowerCase();
      return h || null;
    } catch {
      return null;
    }
  }
  const scp = /^(?:[^@/\s]+@)?([A-Za-z0-9.-]+):(?!\/\/)/.exec(u);
  if (scp && scp[1].includes('.')) return scp[1].toLowerCase();
  return null;
}

/** Walk up from `dir` to the nearest `.git` (a directory or a worktree pointer);
 *  with `walkUp: false`, only `dir` itself. */
function findGitConfig(dir: string, walkUp = true): string | null {
  let cur = path.resolve(dir);
  for (let i = 0; i < (walkUp ? 64 : 1); i++) {
    const dotGit = path.join(cur, '.git');
    const direct = readSmallFile(path.join(dotGit, 'config'), 1_000_000);
    if (direct !== null) return direct;
    const pointer = readSmallFile(dotGit, 4096);
    const m = pointer && /^gitdir:\s*(.+?)\s*$/m.exec(pointer);
    if (m) {
      let gitDir = path.resolve(cur, m[1]);
      const common = readSmallFile(path.join(gitDir, 'commondir'), 4096);
      if (common !== null) gitDir = path.resolve(gitDir, common.trim());
      return readSmallFile(path.join(gitDir, 'config'), 1_000_000);
    }
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
  return null;
}

const cache = new Map<string, GitRemote[]>();

/** Every remote of the repository that contains `dir` (or, with
 *  `walkUp: false`, whose root is `dir`). Cached per process. */
export function readGitRemotes(
  dir: string | undefined,
  opts: { walkUp?: boolean } = {}
): GitRemote[] {
  if (!dir) return [];
  const walkUp = opts.walkUp !== false;
  const key = `${walkUp ? 'up' : 'at'}:${path.resolve(dir)}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const out: GitRemote[] = [];
  try {
    const cfg = findGitConfig(path.resolve(dir), walkUp);
    if (cfg !== null) {
      let current: GitRemote | null = null;
      for (const line of cfg.split(/\r?\n/)) {
        const sec = /^\s*\[\s*([^\]\s]+)(?:\s+"([^"]*)")?\s*\]/.exec(line);
        if (sec) {
          current =
            sec[1].toLowerCase() === 'remote' && sec[2]
              ? { name: sec[2], urls: [], hosts: [], repos: [] }
              : null;
          if (current) out.push(current);
          continue;
        }
        const url = current && /^\s*(?:push)?url\s*=\s*(.+?)\s*$/i.exec(line);
        if (url && current) {
          current.urls.push(url[1]);
          const h = gitRemoteHost(url[1]);
          if (h && !current.hosts.includes(`host:${h}`)) current.hosts.push(`host:${h}`);
          const repo = gitRepoPath(url[1]);
          if (repo && !current.repos.includes(repo)) current.repos.push(repo);
        }
      }
    }
  } catch {
    /* an unreadable repository is no repository */
  }
  cache.set(key, out);
  return out;
}

/** The `host:` destinations of every remote, for the "known" set. */
export function ownRemoteHosts(dir: string | undefined): Set<string> {
  const s = new Set<string>();
  for (const r of readGitRemotes(dir)) for (const h of r.hosts) s.add(h);
  return s;
}

export function _resetGitRemotesCache(): void {
  cache.clear();
}
