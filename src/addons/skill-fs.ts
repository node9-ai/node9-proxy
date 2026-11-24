// src/addons/skill-fs.ts
// The file reads the add-ons inventory (collect.ts) and the approved-list
// gate in the agent hook (resolve.ts) share: skill folders, a skill's name,
// Claude Code's installed plugins. Kept apart from collect.ts so the hook
// bundle carries none of the collector's imports (agent configs, the CLI
// setup they reach); the hook loads this module only for a Skill call.
// Read-only and bounded; every failure yields less data, never a throw.

import fs from 'fs';
import path from 'path';
import { parseFrontmatter } from '../ci-check/frontmatter';

export const MAX_SKILLS = 200;
export const MAX_PLUGINS = 100;
export const MAX_NAME = 128;
export const SKILL_SEARCH_DEPTH = 4;
export const MAX_MD_BYTES = 256 * 1024;

/** Printable, bounded label text. */
export function label(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const t = v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return t ? t.slice(0, MAX_NAME) : null;
}

/**
 * A regular file's text, read through one descriptor: no symlink is followed,
 * and the type and size checked are those of the file read (a check by path
 * and a read by path could see two different files). O_NONBLOCK keeps a FIFO
 * from blocking the open; fstat then rejects it.
 */
export function readText(file: string): string | null {
  let fd: number | undefined;
  try {
    const c = fs.constants;
    fd = fs.openSync(file, c.O_RDONLY | (c.O_NOFOLLOW ?? 0) | (c.O_NONBLOCK ?? 0));
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > MAX_MD_BYTES) return null;
    const buf = Buffer.alloc(st.size);
    const n = fs.readSync(fd, buf, 0, st.size, 0);
    return buf.subarray(0, n).toString('utf8');
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function isDir(p: string): boolean {
  try {
    return fs.lstatSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Skill folders under a root: a directory holding SKILL.md. Symlinks are not
 *  followed; a skill's own sub-folders are not searched for more skills. */
export function findSkillDirs(
  root: string,
  depth = SKILL_SEARCH_DEPTH,
  out: string[] = [],
  limit = MAX_SKILLS
): string[] {
  if (depth < 0 || out.length >= limit || !isDir(root)) return out;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return out;
  }
  if (entries.some((e) => e.isFile() && e.name.toLowerCase() === 'skill.md')) {
    out.push(root);
    return out;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const e of entries) {
    if (out.length >= limit) break;
    if (e.isDirectory() && e.name !== 'node_modules' && e.name !== '.git')
      findSkillDirs(path.join(root, e.name), depth - 1, out, limit);
  }
  return out;
}

export function skillMdPath(dir: string): string | null {
  try {
    const f = fs.readdirSync(dir).find((n) => n.toLowerCase() === 'skill.md');
    return f ? path.join(dir, f) : null;
  } catch {
    return null;
  }
}

/** The name a skill folder reports: its front matter `name`, else the folder. */
export function skillNameOf(dir: string): string | null {
  const mdPath = skillMdPath(dir);
  const md = mdPath ? readText(mdPath) : null;
  const fm = md ? parseFrontmatter(md) : null;
  return label(fm?.name) ?? label(path.basename(dir));
}

export interface InstalledPlugin {
  key: string;
  name: string;
  marketplace: string;
  version?: string;
  installPath?: string;
}

/** Claude Code's installed plugins (`~/.claude/plugins/installed_plugins.json`).
 *  A marketplace folder holds the whole catalog, installed or not, so it is
 *  never read as the installed list. Accepts the map-of-object and the
 *  map-of-array shapes. */
export function installedPlugins(home: string): InstalledPlugin[] {
  const pluginsRoot = path.join(home, '.claude', 'plugins');
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(path.join(pluginsRoot, 'installed_plugins.json'), 'utf8'));
  } catch {
    return [];
  }
  const map = (raw as { plugins?: unknown })?.plugins;
  if (!map || typeof map !== 'object' || Array.isArray(map)) return [];
  const out: InstalledPlugin[] = [];
  for (const [key, val] of Object.entries(map as Record<string, unknown>)) {
    if (out.length >= MAX_PLUGINS) break;
    const at = key.lastIndexOf('@');
    const name = label(at > 0 ? key.slice(0, at) : key);
    const marketplace = label(at > 0 ? key.slice(at + 1) : '') ?? 'unknown';
    if (!name) continue;
    const first = (Array.isArray(val) ? val[0] : val) as
      { version?: unknown; installPath?: unknown } | undefined;
    const ip = typeof first?.installPath === 'string' ? path.resolve(first.installPath) : undefined;
    // Only a folder under ~/.claude/plugins is hashed or searched: the file is
    // data, and a path elsewhere is not followed.
    const inside = ip && (ip + path.sep).startsWith(pluginsRoot + path.sep) ? ip : undefined;
    out.push({
      key,
      name,
      marketplace,
      ...(label(first?.version) ? { version: label(first?.version)!.slice(0, 64) } : {}),
      ...(inside ? { installPath: inside } : {}),
    });
  }
  return out;
}
