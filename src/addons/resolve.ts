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

import os from 'os';
import path from 'path';
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

/**
 * The approved list's verdict on one hook call: an MCP tool by its server's
 * identity, a Claude Code `Skill` call by the skill's folder. Allow when the
 * list enforces nothing (no blocks, unapproved off or log), before any file
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
  } catch {
    /* an unreadable config or folder judges nothing */
  }
  return ALLOW;
}
