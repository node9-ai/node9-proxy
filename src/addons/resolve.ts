// src/addons/resolve.ts
// Which add-on an agent's tool call uses, for the approved list
// (node9Firewall#376 item 6, phase 3). The agent hook calls this; the MCP
// gateway knows its own server and does not.
//
//   mcp__<server>__<tool>  the server entries of that name in the agents'
//                          configs, by identity, from the index the inventory
//                          writes (index-file.ts). Servers that run through the
//                          node9 gateway are left to it (it sees every call and
//                          holds one review per session); a name in no config
//                          (an agent's own built-in server) is not an add-on.
//   Skill { skill }        Claude Code loads a skill through this tool call. The
//                          skill's folder is found by name and hashed now, so a
//                          copy that changed after the last report is judged as
//                          it is. A name with no folder is built into the agent
//                          or the app, not an add-on.
//
// Read-only and bounded; any failure yields "nothing to judge", never a throw:
// node9 failing must never stop the agent.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { collectFileAccesses, normalizeFilePath } from '@node9/policy-engine';
import { hashSkillRoot } from '../skill-pin';
import { readMcpIndex } from './index-file';
import { claudeMcpEntries } from './claude-mcp';
import {
  addonPolicyEnforces,
  mcpVerdict,
  skillVerdict,
  stricter,
  type AddonPolicy,
  type AddonVerdict,
} from './policy';

const ALLOW: AddonVerdict = { action: 'allow' };

/** How an agent spells a config's server name inside `mcp__<name>__<tool>`. */
export function toolServerName(configName: string): string {
  return configName.replace(/[^A-Za-z0-9_-]/g, '_');
}

/** The agent ids the add-ons inventory files a server under, by the name the
 *  hook gives the calling agent. */
const AGENT_ID: Record<string, string> = {
  'Claude Code': 'claude',
  Codex: 'codex',
  'Gemini CLI': 'gemini',
  Antigravity: 'antigravity',
  'GitHub Copilot': 'copilot',
  Cursor: 'cursor',
  Windsurf: 'windsurf',
  VSCode: 'vscode',
  'Claude Desktop': 'claudeDesktop',
  Hermes: 'hermes',
  'Hermes Agent': 'hermes',
  OpenCode: 'opencode',
  Pi: 'pi',
};

/**
 * The identities of the servers named `server` that the hook must judge: in
 * the calling agent's config when it has one by that name, else in any. None
 * when every such entry runs through the gateway, or no config names it.
 * Claude Code's own config files are read now (claude-mcp.ts), so a server
 * renamed or added since the last report is still judged; other agents come
 * from the inventory index.
 */
export function mcpIdentitiesForHook(
  server: string,
  agentLabel: string | undefined,
  home: string = os.homedir(),
  cwd?: string
): string[] {
  const id = agentLabel ? AGENT_ID[agentLabel] : undefined;
  const entries = [
    ...(id === 'claude' || id === undefined ? claudeMcpEntries(cwd, home) : []),
    ...readMcpIndex(home),
  ];
  const named = entries.filter((e) => toolServerName(e.name) === server);
  const own = id ? named.filter((e) => e.agents.includes(id)) : [];
  const out = new Set<string>();
  for (const e of own.length ? own : named) if (e.state !== 'governed') out.add(e.identity);
  return [...out];
}

export interface SkillUse {
  name: string;
  hash: string;
  plugin?: { key: string; versionId: string };
}

type SkillFs = typeof import('./skill-fs.js');

/** The skills under `root` an agent may call `name`: by front matter name or
 *  by folder name. Each keeps the name the add-ons report gives it, which is
 *  the name the approved list files it under. */
function skillUsesNamed(
  sfs: SkillFs,
  root: string,
  name: string,
  plugin?: SkillUse['plugin']
): SkillUse[] {
  const out: SkillUse[] = [];
  for (const dir of sfs.findSkillDirs(root)) {
    const reported = sfs.skillNameOf(dir);
    if (!reported || (reported !== name && path.basename(dir) !== name)) continue;
    const h = hashSkillRoot(dir);
    if (h.exists) out.push({ name: reported, hash: h.contentHash, ...(plugin ? { plugin } : {}) });
  }
  return out;
}

/** The project folders Claude Code reads `.claude/skills` from: the working
 *  directory and its parents, below the home folder. */
function projectDirs(cwd: string | undefined, home: string): string[] {
  if (!cwd || !path.isAbsolute(cwd)) return [];
  const out: string[] = [];
  let dir = path.resolve(cwd);
  for (let i = 0; i < 32; i++) {
    if (dir === home) break;
    out.push(dir);
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return out;
}

/**
 * The skill folders a Claude Code `Skill` call may load, with their hashes.
 * `plugin:skill` is a plugin's skill (or a synced one, under the user skills
 * folder); a bare name is a project or user skill. Every folder that answers
 * to the name is returned, so the stricter verdict wins when two do.
 */
export async function resolveSkillUses(
  skillArg: string,
  cwd: string | undefined,
  home: string = os.homedir()
): Promise<SkillUse[]> {
  // Loaded here, not at the top: the front matter parser and its YAML library
  // stay out of every other hook call.
  const sfs = await import('./skill-fs.js');
  const arg = skillArg.trim().replace(/^\//, '');
  if (!arg) return [];
  const userRoot = path.join(home, '.claude', 'skills');
  const out: SkillUse[] = [];
  const colon = arg.indexOf(':');
  if (colon > 0) {
    const prefix = arg.slice(0, colon);
    const name = arg.slice(colon + 1);
    const plugins = sfs.installedPlugins(home).filter((p) => p.name === prefix);
    for (const p of plugins) {
      if (!p.installPath) continue;
      const h = hashSkillRoot(p.installPath);
      const plugin = {
        key: `${p.name}@${p.marketplace}`,
        // The version id the add-ons report gives the plugin row.
        versionId: h.exists ? h.contentHash : `v:${p.version ?? '?'}`,
      };
      out.push(...skillUsesNamed(sfs, path.join(p.installPath, 'skills'), name, plugin));
    }
    if (plugins.length === 0) out.push(...skillUsesNamed(sfs, userRoot, name));
    return out;
  }
  for (const dir of projectDirs(cwd, home))
    out.push(...skillUsesNamed(sfs, path.join(dir, '.claude', 'skills'), arg));
  out.push(...skillUsesNamed(sfs, userRoot, arg));
  return out;
}

/** `p` is strictly below `root`. path.relative compares with the platform's
 *  rules (case-insensitive on Windows, either separator). */
function inside(p: string, root: string): boolean {
  const rel = path.relative(root, p);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

// A Windows path: drive letter (C:\, C:/) or UNC (\\server\share).
const WIN_PATH = /^(?:[A-Za-z]:[\\/]|\\\\)/;

/**
 * The absolute path a read names. The policy engine's normalizer is POSIX
 * only: it glues the working directory in front of `C:\...` and its shell
 * parser drops the backslashes of an unquoted Windows path. On Windows a
 * Windows-shaped path is resolved with Windows rules instead.
 */
function readTarget(p: string, cwd: string, home: string): string {
  if (process.platform === 'win32' && (WIN_PATH.test(p) || WIN_PATH.test(cwd))) {
    const expanded = p === '~' || /^~[\\/]/.test(p) ? home + p.slice(1) : p;
    return path.resolve(cwd, expanded);
  }
  return normalizeFilePath(p, cwd, home);
}

// SKILL.md paths written into a command, for Windows only, where the shell
// is not bash and a parse as bash loses the backslashes. Quoted or bare,
// either separator; anything found must still sit in a skill folder below.
const WIN_SKILL_IN_COMMAND =
  /(?:"([^"]*?skill\.md)"|'([^']*?skill\.md)'|((?:[A-Za-z]:|\\\\)[^\s"'`|;&<>]*?skill\.md))(?=$|[\s"'`|;&<>)])/gi;

function windowsSkillPathsInCommand(toolInput: unknown): string[] {
  const command = (toolInput as { command?: unknown } | null)?.command;
  if (typeof command !== 'string') return [];
  const out: string[] = [];
  for (const m of command.matchAll(WIN_SKILL_IN_COMMAND)) {
    const p = m[1] ?? m[2] ?? m[3];
    if (p && WIN_PATH.test(p)) out.push(path.resolve(p));
  }
  return out;
}

function realDir(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

/**
 * The skills a call loads by reading their SKILL.md directly, for agents with
 * no skill tool: Codex loads a skill by reading the file through the shell.
 * Claude Code loads skills through its Skill tool (and a typed slash
 * command), and its Read of a SKILL.md is how a skill gets edited, so it is
 * not judged here: under the block rule nobody could edit a skill they are
 * writing. A SKILL.md counts only inside a folder the agents load skills
 * from (the user's, a plugin's, the project's), compared after resolving
 * links; a skill anywhere else (a repository under review) is a file. Codex's
 * own system skills (`~/.codex/skills/.system`) are built in, not add-ons.
 */
export async function skillReadUses(
  toolName: string,
  toolInput: unknown,
  cwd: string | undefined,
  home: string = os.homedir()
): Promise<SkillUse[]> {
  const base = cwd && path.isAbsolute(cwd) ? cwd : home;
  const read = collectFileAccesses(toolName, toolInput, { cwd: base, homeDirs: [home] })
    .filter((a) => a.operation === 'read' && !a.listing)
    .flatMap((a) =>
      a.candidates && !(process.platform === 'win32' && WIN_PATH.test(a.path))
        ? a.candidates
        : [readTarget(a.path, a.cwd ?? base, home)]
    )
    .concat(process.platform === 'win32' ? windowsSkillPathsInCommand(toolInput) : [])
    .filter((p) => path.isAbsolute(p) && path.basename(p).toLowerCase() === 'skill.md');
  if (read.length === 0) return [];
  const sfs = await import('./skill-fs.js');
  const roots: Array<{
    root: string;
    plugin?: { name: string; marketplace: string; installPath: string; version?: string };
  }> = [
    { root: path.join(home, '.claude', 'skills') },
    { root: path.join(home, '.codex', 'skills') },
    { root: path.join(home, '.agents', 'skills') },
    ...projectDirs(cwd, home).flatMap((d) => [
      { root: path.join(d, '.claude', 'skills') },
      { root: path.join(d, '.agents', 'skills') },
    ]),
  ];
  for (const p of sfs.installedPlugins(home))
    if (p.installPath)
      roots.push({
        root: path.join(p.installPath, 'skills'),
        plugin: {
          name: p.name,
          marketplace: p.marketplace,
          installPath: p.installPath,
          version: p.version,
        },
      });
  const realRoots = roots.map((r) => ({ ...r, real: realDir(r.root) }));
  const builtIn = path.join(home, '.codex', 'skills', '.system');
  const builtInReal = realDir(builtIn);
  const out: SkillUse[] = [];
  for (const file of new Set(read)) {
    const dir = path.dirname(file);
    const real = realDir(dir);
    const isIn = (p: string, root: string) => p === root || inside(p, root);
    if (isIn(dir, builtIn) || isIn(real, builtInReal)) continue;
    const where = realRoots.find((r) => inside(dir, r.root) || inside(real, r.real));
    if (!where) continue;
    const name = sfs.skillNameOf(real);
    const h = hashSkillRoot(real);
    if (!name || !h.exists) continue;
    let plugin: SkillUse['plugin'];
    if (where.plugin) {
      // Hashed only for the plugin the file is in.
      const ph = hashSkillRoot(where.plugin.installPath);
      plugin = {
        key: `${where.plugin.name}@${where.plugin.marketplace}`,
        versionId: ph.exists ? ph.contentHash : `v:${where.plugin.version ?? '?'}`,
      };
    }
    out.push({ name, hash: h.contentHash, ...(plugin ? { plugin } : {}) });
  }
  return out;
}

/**
 * The approved list's verdict on one hook call: an MCP tool by its server's
 * identity, a Claude Code `Skill` call by the skill's folder, another agent's
 * read of a skill's SKILL.md by that skill. Allow when the list enforces nothing (no blocks, unapproved off or log), before any file
 * is read.
 */
export async function addonVerdictForHookCall(
  policy: AddonPolicy | undefined,
  call: {
    toolName: string;
    toolInput: unknown;
    mcpServer?: string;
    agent?: string;
    cwd?: string;
  },
  home: string = os.homedir()
): Promise<AddonVerdict> {
  if (!addonPolicyEnforces(policy)) return ALLOW;
  try {
    if (call.mcpServer) {
      let v = ALLOW;
      for (const id of mcpIdentitiesForHook(call.mcpServer, call.agent, home, call.cwd))
        v = stricter(v, mcpVerdict(policy, id));
      return v;
    }
    if (call.toolName === 'Skill') {
      const input = call.toolInput as { skill?: unknown } | null;
      if (typeof input?.skill !== 'string') return ALLOW;
      let v = ALLOW;
      for (const use of await resolveSkillUses(input.skill, call.cwd, home))
        v = stricter(v, skillVerdict(policy, use));
      return v;
    }
    // Claude Code loads skills through the Skill tool (above); see skillReadUses.
    if (call.agent === 'Claude Code') return ALLOW;
    let v = ALLOW;
    for (const use of await skillReadUses(call.toolName, call.toolInput, call.cwd, home))
      v = stricter(v, skillVerdict(policy, use));
    return v;
  } catch {
    /* an unreadable config or folder judges nothing */
  }
  return ALLOW;
}
