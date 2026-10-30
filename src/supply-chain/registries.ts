// The package registries the user configured (node9Firewall#415 item 4).
//
// An install that names a registry on its command line (`npm i --registry
// https://<host> pkg`) is judged by loading.unknown-registry, and a host the
// user already set up is not unknown. "Set up" means what the package
// managers themselves read: the npm, yarn and bun config files, pip's and
// uv's config files, the project's pyproject.toml / Pipfile sources, and the
// variables those tools read from the environment the agent runs in. Every
// http(s) URL on a registry, index, source or mirror line counts; the file
// formats are not parsed beyond that, since a URL on such a line is a
// registry the user wrote down.
//
// Known limit: a registry the agent writes into one of these files in an
// earlier call is "configured" by then. The package manager reads the file
// without any flag, so the flag check could not have seen it either.

import os from 'os';
import path from 'path';
import fs from 'fs';
import { registryHost } from '@node9/policy-engine';
import { readCappedText } from '../utils/read-capped';

const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_PARENT_DIRS = 12;
const TTL_MS = 5_000;

/** Config files looked for in the working directory and each parent. */
const PROJECT_FILES = [
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
  'bunfig.toml',
  'pip.conf',
  'uv.toml',
  'pyproject.toml',
  'Pipfile',
];
const ENV_VARS = [
  'npm_config_registry',
  'NPM_CONFIG_REGISTRY',
  'YARN_REGISTRY',
  'YARN_NPM_REGISTRY_SERVER',
  'BUN_CONFIG_REGISTRY',
  'PIP_INDEX_URL',
  'PIP_EXTRA_INDEX_URL',
  'PIP_FIND_LINKS',
  'UV_INDEX_URL',
  'UV_EXTRA_INDEX_URL',
  'UV_INDEX',
  'UV_DEFAULT_INDEX',
  'PIPENV_PYPI_MIRROR',
];
const REGISTRY_LINE_RE = /registry|index|url|source|mirror|find-links/i;
const URL_RE = /https?:\/\/[^\s"'<>,;]+/gi;

function userFiles(home: string, env: NodeJS.ProcessEnv): string[] {
  const xdg = env.XDG_CONFIG_HOME || path.join(home, '.config');
  return [
    env.NPM_CONFIG_USERCONFIG || env.npm_config_userconfig || path.join(home, '.npmrc'),
    path.join(home, '.yarnrc'),
    path.join(home, '.yarnrc.yml'),
    path.join(home, '.bunfig.toml'),
    env.PIP_CONFIG_FILE || '',
    path.join(xdg, 'pip', 'pip.conf'),
    path.join(home, '.pip', 'pip.conf'),
    '/etc/pip.conf',
    env.VIRTUAL_ENV ? path.join(env.VIRTUAL_ENV, 'pip.conf') : '',
    env.UV_CONFIG_FILE || '',
    path.join(xdg, 'uv', 'uv.toml'),
    '/etc/uv/uv.toml',
  ].filter(Boolean);
}

function projectFiles(cwd: string | undefined): string[] {
  if (!cwd || !path.isAbsolute(cwd)) return [];
  const out: string[] = [];
  let dir = cwd;
  for (let i = 0; i < MAX_PARENT_DIRS; i++) {
    for (const f of PROJECT_FILES) out.push(path.join(dir, f));
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return out;
}

function hostsInText(text: string, out: Set<string>): void {
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (t.startsWith('#') || t.startsWith(';') || !REGISTRY_LINE_RE.test(t)) continue;
    for (const m of t.matchAll(URL_RE)) {
      const host = registryHost(m[0]);
      if (host) out.add(host);
    }
  }
}

const cache = new Map<string, { at: number; hosts: Set<string> }>();

/** The registry hosts the user's own configuration names. Never throws. */
export function configuredRegistryHosts(
  cwd?: string,
  env: NodeJS.ProcessEnv = process.env,
  home: string = os.homedir()
): Set<string> {
  const key = `${cwd ?? ''}\u0000${home}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.hosts;
  const hosts = new Set<string>();
  for (const name of ENV_VARS) {
    const v = env[name];
    if (!v) continue;
    for (const url of v.split(/\s+/)) {
      const host = registryHost(url);
      if (host) hosts.add(host);
    }
  }
  for (const file of [...userFiles(home, env), ...projectFiles(cwd)]) {
    // O_NONBLOCK: a FIFO at the path must not hang the gate on open.
    const r = readCappedText(
      file,
      MAX_CONFIG_BYTES,
      fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0)
    );
    if (r) hostsInText(r.text, hosts);
  }
  cache.set(key, { at: Date.now(), hosts });
  return hosts;
}

/** Test seam: forget the cached reads. */
export function _resetRegistryCache(): void {
  cache.clear();
}
