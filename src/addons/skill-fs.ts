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
import { label } from './installed-plugins';

// Re-exported: the collector and the resolver read them from here.
export { installedPlugins, label, type InstalledPlugin } from './installed-plugins';

export const MAX_SKILLS = 200;
export const MAX_NAME = 128;
export const SKILL_SEARCH_DEPTH = 4;
export const MAX_MD_BYTES = 256 * 1024;

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
