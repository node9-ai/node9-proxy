// src/addons/collect.ts
// The add-ons inventory (fw#376 item 6, add-ons plan phase 1): which skills,
// Claude Code plugins and MCP servers this machine's agents load. Shipped in
// the policy snapshot so the dashboard can list them across machines.
//
// What leaves the machine: names, content hashes, file counts, rule ids with
// a severity, the `allowed-tools` a skill grants itself, and an MCP identity
// (package, image, host or program name). What never leaves: file text,
// command arguments, env values and paths (a project skill is reported by
// name and hash only). Read-only and bounded; every failure yields less data,
// never a throw.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { hashSkillRoot } from '../skill-pin';
import { analyzeInstructionFile, analyzeWithdrawnGuidance } from '../ci-check/instructions';
import { parseFrontmatter, allowedToolsOf } from '../ci-check/frontmatter';
import { observeAudit } from '../apps/detect';
import { inventoryMcp, entryUpstream } from '../mcp-wrap';
import { substituteEnv } from '../mcp-status';
import { getServerKey } from '../mcp-pin';
import { tokenize } from '../mcp-cmd';
import { scanText } from '../dlp';
import {
  mcpIdentityFromCommand,
  mcpIdentityFromUrl,
  mcpPackageFromCommand,
  type McpPackage,
} from './identity';
import { readStanding } from './standing-file';
import { readDefinitionScans } from './definitions-file';
import { skillHosts, type SkillHost } from './skill-hosts';
import { lookupDomainsRound } from './host-lookup';
import {
  MAX_SKILLS,
  SKILL_SEARCH_DEPTH,
  findSkillDirs,
  installedPlugins,
  label,
  readText,
  skillMdPath,
} from './skill-fs';

// Re-exported: the collector's tests and callers read them from here.
export { findSkillDirs, installedPlugins, skillNameOf } from './skill-fs';

export type SkillScope = 'user' | 'plugin' | 'project';
export type SkillSource = 'synced' | 'built-in';

export interface AddonSkill {
  /** The agent that loads it: claude, codex, or shared (the ~/.agents layout). */
  agent: string;
  scope: SkillScope;
  name: string;
  /** For a plugin skill: `<plugin>@<marketplace>`. Else where it came from,
   *  when the folder says so (`synced` from claude.ai, `built-in` to Codex). */
  source?: string;
  hash: string;
  fileCount: number;
  /** Rule id and severity, one per rule (the worst), never the text. */
  findings: Array<{ rule: string; severity: string }>;
  /** The skill's own `allowed-tools` grant. */
  grants?: string[];
  /** The checks that ran for this skill (phase 4). `hosts`: DNS was asked
   *  about the domains it names. Absent when none ran. */
  checks?: Array<'hosts'>;
  /** Domains the skill names that DNS says nobody registered. Never sent
   *  for a project skill (plan D5: name and hash only). */
  unregisteredDomains?: string[];
}

export interface AddonPlugin {
  name: string;
  marketplace: string;
  version?: string;
  enabled?: boolean;
  hash?: string;
}

export interface AddonMcp {
  name: string;
  /** `npm:<pkg>`, `pypi:<pkg>`, `docker:<image>`, `url:<host>`, `binary:<prog>`... */
  identity: string;
  agents: string[];
  /** governed = runs through the node9 gateway; outside = spawned directly;
   *  remote = a URL server node9 cannot wrap. */
  state: 'governed' | 'outside' | 'remote';
  /** For a governed server: the key the mcpServers rows carry, to join them. */
  serverKey?: string;
  /** What the checks named in `checks` found (phase 4). Absent when none ran. */
  findings?: Array<{ rule: string; severity: string }>;
  /** The checks that ran for this server, so no finding reads as "nothing
   *  found" only for a check that is listed. `package`: the package check
   *  got an answer from the registry (or found something anyway).
   *  `definitions`: the gateway scanned the server's tool definitions. */
  checks?: Array<'package' | 'definitions'>;
}

/** One configured server with the package the check looks up, when it has one. */
export interface McpDetail {
  entry: AddonMcp;
  pkg: McpPackage | null;
}

export interface AddonsReport {
  skills: AddonSkill[];
  plugins: AddonPlugin[];
  mcp: AddonMcp[];
  /** True when a cap cut the list short. */
  capped?: boolean;
}

const MAX_MCP = 100;
const MAX_GRANTS = 30;
const MAX_MD_PER_SKILL = 50;
const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  advisory: 1,
  info: 0,
};

function mdFiles(dir: string, depth = 3, out: string[] = []): string[] {
  if (depth < 0 || out.length >= MAX_MD_PER_SKILL) return out;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (out.length >= MAX_MD_PER_SKILL) break;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) mdFiles(p, depth - 1, out);
    else if (e.isFile() && /\.md$/i.test(e.name)) out.push(p);
  }
  return out;
}

/** One skill folder as a report row. */
export function describeSkill(
  dir: string,
  agent: string,
  scope: SkillScope,
  source?: string,
  /** When given, receives the domains the skill names (skill-hosts.ts), for
   *  the host check. They never go on the row from here. */
  hostsOut?: Map<AddonSkill, SkillHost[]>
): AddonSkill | null {
  const mdPath = skillMdPath(dir);
  const md = mdPath ? readText(mdPath) : null;
  const fm = md ? parseFrontmatter(md) : null;
  const name = label(fm?.name) ?? label(path.basename(dir));
  if (!name) return null;
  const h = hashSkillRoot(dir);
  if (!h.exists) return null;

  const worst = new Map<string, string>();
  const add = (rule: string, severity: string): void => {
    const cur = worst.get(rule);
    if (!cur || (SEVERITY_RANK[severity] ?? 0) > (SEVERITY_RANK[cur] ?? 0))
      worst.set(rule, severity);
  };
  if (md && mdPath) for (const f of analyzeInstructionFile('SKILL.md', md)) add(f.rule, f.severity);
  const texts: string[] = [];
  for (const file of mdFiles(dir)) {
    const text = readText(file);
    if (!text) continue;
    for (const f of analyzeWithdrawnGuidance('skill', text)) add(f.rule, f.severity);
    if (hostsOut) texts.push(text);
  }
  // A grant is text the skill's author wrote (`Bash(curl -H "Authorization: ...")`),
  // so one that carries a credential keeps its tool name only.
  const grants = allowedToolsOf(fm)
    .map((g) => (scanText(g) ? `${g.split('(')[0]}(redacted)` : g))
    .map((g) => label(g))
    .filter((g): g is string => !!g)
    .slice(0, MAX_GRANTS);

  const row: AddonSkill = {
    agent,
    scope,
    name,
    ...(source ? { source } : {}),
    hash: h.contentHash,
    fileCount: h.fileCount,
    findings: [...worst].map(([rule, severity]) => ({ rule, severity })),
    ...(grants.length ? { grants } : {}),
  };
  if (hostsOut) {
    try {
      hostsOut.set(row, skillHosts(texts));
    } catch {
      /* a text the extractor chokes on names no host */
    }
  }
  return row;
}

/** Where a user-level skill came from, when its folder says so. */
function userSource(root: string, dir: string): string | undefined {
  const rel = path.relative(root, dir).split(path.sep);
  if (rel[0] === 'synced') return 'synced';
  if (rel[0] === '.system') return 'built-in';
  return undefined;
}

function enabledPlugins(home: string): Record<string, boolean> {
  try {
    const s = JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8')) as {
      enabledPlugins?: unknown;
    };
    const e = s.enabledPlugins;
    if (!e || typeof e !== 'object' || Array.isArray(e)) return {};
    const out: Record<string, boolean> = {};
    for (const [k, v] of Object.entries(e as Record<string, unknown>))
      if (typeof v === 'boolean') out[k] = v;
    return out;
  } catch {
    return {};
  }
}

/** The project folders agent sessions were started in lately (from the audit
 *  log): where an agent loads project skills from. Not every folder a call
 *  ran in: an agent that `cd`s into a repository it is only reading (a
 *  checkout under review) does not load that repository's skills, and
 *  listing them filled the inventory with add-ons nobody uses. */
function recentProjects(home: string): string[] {
  try {
    return observeAudit(path.join(home, '.node9', 'audit.log')).launchDirs.filter(
      (d) => path.isAbsolute(d) && d !== home
    );
  } catch {
    return [];
  }
}

/** The configured servers, each with its package when it runs one. Config
 *  reads only: no file hashing, no network. */
export function collectMcpDetail(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env
): McpDetail[] {
  let entries: ReturnType<typeof inventoryMcp>;
  try {
    entries = inventoryMcp(home);
  } catch {
    return [];
  }
  const byKey = new Map<string, McpDetail>();
  for (const e of entries) {
    if (e.state === 'node9-self') continue;
    let identity: string;
    let serverKey: string | undefined;
    let state: AddonMcp['state'];
    let pkg: McpPackage | null = null;
    if (e.state === 'remote') {
      const raw = (e.raw ?? {}) as Record<string, unknown>;
      identity = mcpIdentityFromUrl(raw.url ?? raw.httpUrl ?? raw.serverUrl);
      state = 'remote';
    } else if (e.state === 'gatewayed') {
      const upstream = entryUpstream(e);
      if (!upstream) continue;
      const [command, ...args] = tokenize(upstream);
      identity = mcpIdentityFromCommand(command ?? '', args);
      pkg = mcpPackageFromCommand(command ?? '', args);
      serverKey = getServerKey(substituteEnv(upstream, env).resolved);
      state = 'governed';
    } else {
      identity = mcpIdentityFromCommand(e.command, e.args);
      pkg = mcpPackageFromCommand(e.command, e.args);
      state = 'outside';
    }
    const name = label(e.name) ?? identity;
    const key = `${name}\0${identity}\0${state}`;
    const row = byKey.get(key);
    if (row) {
      if (!row.entry.agents.includes(e.agent)) row.entry.agents.push(e.agent);
      continue;
    }
    if (byKey.size >= MAX_MCP) break;
    byKey.set(key, {
      entry: {
        name,
        identity,
        agents: [e.agent],
        state,
        ...(serverKey ? { serverKey } : {}),
      },
      pkg,
    });
  }
  return [...byKey.values()];
}

/** The MCP rows of the report, with what the checks last found for each:
 *  the package check (standing-file.ts, written by the daemon) and the scan
 *  of tool definitions (definitions-file.ts, written by the gateway).
 *  Advisory ids stay on the machine: the report carries rule ids and
 *  severities, as for skills. */
function collectMcp(home: string, env: NodeJS.ProcessEnv): AddonMcp[] {
  const standing = readStanding(home).entries;
  const definitions = readDefinitionScans(home);
  return collectMcpDetail(home, env).map(({ entry, pkg }) => {
    const checks: NonNullable<AddonMcp['checks']> = [];
    const findings: NonNullable<AddonMcp['findings']> = [];
    const s = pkg ? standing[entry.identity] : undefined;
    // "Checked" only when the registry answered, or something was found anyway.
    if (s && (s.registry || s.findings.length > 0)) {
      checks.push('package');
      for (const f of s.findings) findings.push({ rule: f.rule, severity: f.severity });
    }
    // Only a server that runs through the gateway is scanned: a record left
    // from before it was unwrapped says nothing about what it serves now.
    const d = entry.state === 'governed' ? definitions.get(entry.identity) : undefined;
    if (d) {
      checks.push('definitions');
      for (const f of d.findings) findings.push({ rule: f.rule, severity: f.severity });
    }
    return checks.length > 0 ? { ...entry, findings, checks } : entry;
  });
}

/** The MCP part only, for the index the agent hook reads (index-file.ts):
 *  config reads, no skill hashing, so the daemon can rebuild it often. */
export function collectMcpOnly(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env
): AddonMcp[] {
  return collectMcp(home, env);
}

/** Build the add-ons report for this machine. Never throws. */
export function collectAddons(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env
): AddonsReport {
  return collectAddonsDetail(home, env).report;
}

/** The report, and beside it the domains each skill names: the host check
 *  asks DNS about them (withHostFindings). The domains are not in the report. */
export function collectAddonsDetail(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env
): { report: AddonsReport; hosts: Map<AddonSkill, SkillHost[]> } {
  const hosts = new Map<AddonSkill, SkillHost[]>();
  const skills: AddonSkill[] = [];
  let capped = false;
  const seenDirs = new Set<string>();
  const addSkills = (
    root: string,
    agent: string,
    scope: SkillScope,
    source?: (dir: string) => string | undefined
  ): void => {
    // One past the cap, so a cut list is known to be cut.
    for (const dir of findSkillDirs(root, SKILL_SEARCH_DEPTH, [], MAX_SKILLS + 1)) {
      if (skills.length >= MAX_SKILLS) {
        capped = true;
        return;
      }
      const real = path.resolve(dir);
      if (seenDirs.has(real)) continue;
      seenDirs.add(real);
      try {
        const row = describeSkill(dir, agent, scope, source?.(dir), hosts);
        if (row) skills.push(row);
      } catch {
        /* one unreadable skill never drops the report */
      }
    }
  };

  const claudeRoot = path.join(home, '.claude', 'skills');
  const codexRoot = path.join(home, '.codex', 'skills');
  addSkills(claudeRoot, 'claude', 'user', (d) => userSource(claudeRoot, d));
  addSkills(codexRoot, 'codex', 'user', (d) => userSource(codexRoot, d));
  addSkills(path.join(home, '.agents', 'skills'), 'shared', 'user');

  const plugins: AddonPlugin[] = [];
  const enabled = enabledPlugins(home);
  for (const p of installedPlugins(home)) {
    const h = p.installPath ? hashSkillRoot(p.installPath) : null;
    plugins.push({
      name: p.name,
      marketplace: p.marketplace,
      ...(p.version ? { version: p.version } : {}),
      ...(p.key in enabled ? { enabled: enabled[p.key] } : {}),
      ...(h?.exists ? { hash: h.contentHash } : {}),
    });
    if (p.installPath)
      addSkills(
        path.join(p.installPath, 'skills'),
        'claude',
        'plugin',
        () => `${p.name}@${p.marketplace}`
      );
  }

  for (const dir of recentProjects(home)) {
    addSkills(path.join(dir, '.claude', 'skills'), 'claude', 'project');
    addSkills(path.join(dir, '.agents', 'skills'), 'shared', 'project');
  }

  const mcp = collectMcp(home, env);
  return { report: { skills, plugins, mcp, ...(capped ? { capped: true } : {}) }, hosts };
}

const MAX_DOMAINS_PER_SKILL = 5;

/**
 * Put the host check's answers on the skill rows (phase 4, check B). A skill
 * that names a domain DNS says nobody registered gets a finding: high where
 * the skill has the agent send or fetch something there, low for a plain
 * link. A skill is marked as checked only when every domain it names got an
 * answer, so no finding reads as "nothing found" where nothing was asked.
 * Pure: `answers` come from host-lookup.ts.
 */
export function withHostFindings(
  detail: { report: AddonsReport; hosts: Map<AddonSkill, SkillHost[]> },
  answers: Map<string, boolean | null>
): AddonsReport {
  const skills = detail.report.skills.map((row): AddonSkill => {
    const hosts = detail.hosts.get(row) ?? [];
    const gone = hosts.filter((h) => answers.get(h.domain) === false);
    // Checked only when DNS answered for every domain the skill names: a
    // domain past the round's cap or time, or one the resolver gave no clear
    // answer for, leaves the skill "not checked", never "nothing found".
    const allAnswered = hosts.every((h) => typeof answers.get(h.domain) === 'boolean');
    const checked: AddonSkill = allAnswered ? { ...row, checks: ['hosts'] } : { ...row };
    if (gone.length === 0) return checked;
    return {
      ...checked,
      findings: [
        ...row.findings,
        { rule: 'skill.host-unregistered', severity: gone.some((h) => h.action) ? 'high' : 'low' },
      ],
      ...(row.scope === 'project'
        ? {}
        : { unregisteredDomains: gone.map((h) => h.domain).slice(0, MAX_DOMAINS_PER_SKILL) }),
    };
  });
  return { ...detail.report, skills };
}

/**
 * The report with the host check applied: asks DNS (cached for a day) about
 * the domains the skills name. For the daemon and `node9 policy push`, never
 * a hook. No lookups when the user switched the package check off (the one
 * switch for node9's own network lookups), and none of the rows is marked as
 * checked when the resolver could not be trusted. Never throws.
 */
export async function collectAddonsWithLookups(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env,
  opts: {
    lookupsAllowed?: boolean;
    lookup?: typeof lookupDomainsRound;
  } = {}
): Promise<AddonsReport> {
  const detail = collectAddonsDetail(home, env);
  if (opts.lookupsAllowed === false) return detail.report;
  try {
    const domains = [...new Set([...detail.hosts.values()].flat().map((h) => h.domain))];
    const round = await (opts.lookup ?? lookupDomainsRound)(domains, home);
    return round.ok ? withHostFindings(detail, round.answers) : detail.report;
  } catch {
    return detail.report;
  }
}
