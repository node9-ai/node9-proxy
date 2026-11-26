// src/addons/installed-plugins.ts
// Claude Code's installed plugins and the label rule the add-ons code shares.
// A module with no parser behind it: the agent hook loads it on every call
// (skill pinning reads the installed plugins), so it must stay light.

import fs from 'fs';
import path from 'path';

export const MAX_PLUGINS = 100;
const MAX_NAME = 128;

/** Printable, bounded label text. */
export function label(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const t = v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return t ? t.slice(0, MAX_NAME) : null;
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
