// src/apps/detect.ts
// Find the apps a machine's agents use (node9Firewall#390, phase 2). Names
// only: an MCP server label, the program a command starts with, a package
// name, an env var name. A `.env` line is split at `=` and its value is
// dropped on the spot; nothing here returns, logs or stores a value.
//
// Sources, all bounded:
//  - the tail of ~/.node9/audit.log (5 MB): MCP server labels, the programs
//    Bash commands ran, the working directories (50 newest);
//  - ~/.node9/mcp-tools.json: servers that launched through the gateway;
//  - in each working directory: package.json, requirements.txt,
//    pyproject.toml (dependency names) and .env files (key names), 64 KB each.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { APP_CATALOG, type AppEntry } from './catalog';
import { readMcpToolsConfig } from '../daemon/mcp-tools';

export type SignalKind = 'mcp-server' | 'command' | 'package' | 'env-name';

export interface AppSignal {
  kind: SignalKind;
  /** The name that matched: a server label, a program, a package, an env name. */
  value: string;
  /** The project the package or env name was found in, when there is one. */
  project?: string;
}

export interface FoundApp {
  slug: string;
  signals: AppSignal[];
}

const AUDIT_TAIL_BYTES = 5 * 1024 * 1024;
const MAX_PROJECTS = 50;
const MAX_FILE_BYTES = 64 * 1024;
const MAX_SIGNALS_PER_APP = 6;

const SHELL_TOOLS = new Set([
  'bash',
  'shell',
  'run_shell_command',
  'execute_bash',
  'execute_command',
]);
// Words that run another program: the program after them is the one used.
const WRAPPERS = new Set([
  'sudo',
  'env',
  'time',
  'nohup',
  'exec',
  'command',
  'npx',
  'pnpx',
  'bunx',
]);

export interface Observed {
  servers: Set<string>;
  commands: Set<string>;
  projects: string[];
}

function readTail(file: string, bytes: number): string {
  let fd: number | undefined;
  try {
    fd = fs.openSync(file, 'r');
    const size = fs.fstatSync(fd).size;
    const start = Math.max(0, size - bytes);
    const buf = Buffer.alloc(size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    const text = buf.toString('utf8');
    // Drop a partial first line when the read started mid-file.
    return start > 0 ? text.slice(text.indexOf('\n') + 1) : text;
  } catch {
    return '';
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** The programs a command line starts, one per segment (`a && b | c`). */
export function programsOf(command: string): string[] {
  const out: string[] = [];
  for (const segment of command.split(/&&|\|\||[;|\n]/)) {
    const words = segment.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    while (i < words.length) {
      const w = words[i];
      // An env assignment (NAME=value) or a wrapper's own flag (sudo -E).
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w) || (i > 0 && w.startsWith('-'))) {
        i++;
        continue;
      }
      const base = path.basename(w.replace(/^["']|["']$/g, ''));
      if (WRAPPERS.has(base)) {
        i++;
        continue;
      }
      if (/^[A-Za-z0-9._+-]+$/.test(base)) out.push(base.toLowerCase());
      break;
    }
  }
  return out;
}

/** What the audit log saw: server labels, programs, working directories. */
export function observeAudit(auditFile: string): Observed {
  const servers = new Set<string>();
  const commands = new Set<string>();
  const dirs: string[] = [];
  const seenDirs = new Set<string>();
  const lines = readTail(auditFile, AUDIT_TAIL_BYTES).split('\n');
  // Newest first, so the 50 projects kept are the recent ones.
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line.startsWith('{')) continue;
    let row: { tool?: unknown; argsPreview?: unknown; workingDir?: unknown; mcpServer?: unknown };
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    const tool = typeof row.tool === 'string' ? row.tool : '';
    const ns = /^mcp__([^_](?:[^_]|_(?!_))*?)__/i.exec(tool);
    if (ns) servers.add(ns[1].toLowerCase());
    if (typeof row.mcpServer === 'string' && row.mcpServer)
      servers.add(row.mcpServer.toLowerCase());
    if (SHELL_TOOLS.has(tool.toLowerCase()) && typeof row.argsPreview === 'string') {
      for (const p of programsOf(row.argsPreview)) commands.add(p);
    }
    const dir = typeof row.workingDir === 'string' ? row.workingDir : '';
    if (dir && path.isAbsolute(dir) && !seenDirs.has(dir) && dirs.length < MAX_PROJECTS) {
      seenDirs.add(dir);
      dirs.push(dir);
    }
  }
  return { servers, commands, projects: dirs };
}

function readSmall(file: string): string | null {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/** Dependency names in a project's manifests. */
export function projectPackages(dir: string): Set<string> {
  const out = new Set<string>();
  const pkg = readSmall(path.join(dir, 'package.json'));
  if (pkg) {
    try {
      const j = JSON.parse(pkg) as Record<string, unknown>;
      for (const key of [
        'dependencies',
        'devDependencies',
        'peerDependencies',
        'optionalDependencies',
      ]) {
        const deps = j[key];
        if (deps && typeof deps === 'object')
          for (const name of Object.keys(deps)) out.add(name.toLowerCase());
      }
    } catch {
      // A broken manifest names nothing.
    }
  }
  const req = readSmall(path.join(dir, 'requirements.txt'));
  if (req) {
    for (const line of req.split('\n')) {
      const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line);
      if (m && !line.trim().startsWith('#') && !line.trim().startsWith('-'))
        out.add(m[1].toLowerCase());
    }
  }
  const py = readSmall(path.join(dir, 'pyproject.toml'));
  if (py) {
    // PEP 621 lists ("stripe>=8", "boto3") and Poetry tables (stripe = "^8").
    for (const m of py.matchAll(/["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;[\]]|["'])/g))
      out.add(m[1].toLowerCase());
    let inDeps = false;
    for (const line of py.split('\n')) {
      const section = /^\s*\[([^\]]+)\]/.exec(line);
      if (section) {
        inDeps = /dependencies/.test(section[1]);
        continue;
      }
      const m = inDeps ? /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(line) : null;
      if (m && m[1] !== 'python') out.add(m[1].toLowerCase());
    }
  }
  return out;
}

/** Env var NAMES in a project's .env files. The value is dropped per line. */
export function projectEnvNames(dir: string): Set<string> {
  const out = new Set<string>();
  for (const f of ['.env', '.env.local', '.env.development']) {
    const text = readSmall(path.join(dir, f));
    if (!text) continue;
    for (const line of text.split('\n')) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
      if (m) out.add(m[1].toUpperCase());
    }
  }
  return out;
}

function packageMatches(name: string, wanted: string): boolean {
  return wanted.endsWith('/') ? name.startsWith(wanted) : name === wanted;
}

/** Match what was observed against the catalog. */
export function matchApps(
  obs: Observed,
  projectFacts: Array<{ dir: string; packages: Set<string>; envNames: Set<string> }>,
  catalog: readonly AppEntry[] = APP_CATALOG
): FoundApp[] {
  const found: FoundApp[] = [];
  for (const app of catalog) {
    const signals: AppSignal[] = [];
    const add = (s: AppSignal) => {
      if (signals.length >= MAX_SIGNALS_PER_APP) return;
      if (!signals.some((x) => x.kind === s.kind && x.value === s.value)) signals.push(s);
    };
    for (const server of obs.servers)
      if (app.servers.some((a) => server.includes(a))) add({ kind: 'mcp-server', value: server });
    for (const cmd of app.commands) if (obs.commands.has(cmd)) add({ kind: 'command', value: cmd });
    for (const p of projectFacts) {
      for (const name of p.packages)
        if (app.packages.some((w) => packageMatches(name, w)))
          add({ kind: 'package', value: name, project: p.dir });
      for (const env of p.envNames)
        if (app.envPrefixes.some((pre) => env.startsWith(pre)))
          add({ kind: 'env-name', value: env, project: p.dir });
    }
    if (signals.length > 0) found.push({ slug: app.slug, signals });
  }
  return found;
}

/** Everything, from this machine's files. */
export function detectApps(home: string = os.homedir()): FoundApp[] {
  const obs = observeAudit(path.join(home, '.node9', 'audit.log'));
  for (const cfg of Object.values(readMcpToolsConfig())) {
    if (cfg?.name) obs.servers.add(cfg.name.toLowerCase());
  }
  const facts = obs.projects
    .filter((dir) => {
      try {
        return fs.statSync(dir).isDirectory();
      } catch {
        return false;
      }
    })
    .map((dir) => ({ dir, packages: projectPackages(dir), envNames: projectEnvNames(dir) }));
  return matchApps(obs, facts);
}
