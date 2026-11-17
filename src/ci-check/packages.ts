// src/ci-check/packages.ts
// fw#481 A1, part 1 (pure, no network): the registry packages an agent would fetch and run,
// read from the places it reads them. `scanTree` collects these references; the async step in
// package-check.ts asks the registries and turns the answers into findings.
//
// Two kinds of surface (design scanner-a1-packages-design.md §4.2):
//   auto-run — an MCP server launch, a hook command, a folder-open task, a hook script: it runs in
//              every contributor's session without anyone reading it. Findings here count.
//   text     — instruction files, skill docs, skill scripts: an agent may run the command when it
//              follows the doc. On 775 repositories a third of these hits were true, so they are
//              review items unless the package is known malicious.

import { extractPackageInstalls, type PackageEcosystem } from '@node9/policy-engine';
import { parse as parseToml } from 'smol-toml';
import { lineAtIndex } from './lines';

export type PackageSurface = 'mcp' | 'hook' | 'task' | 'hook-script' | 'skill-script' | 'doc';

export interface PackageRef {
  ecosystem: PackageEcosystem;
  name: string;
  /** Exact pinned version, when the reference names one. */
  version?: string;
  /** The front-end that fetches it: npx, uvx, pip … */
  manager: string;
  surface: PackageSurface;
  autoRun: boolean;
  file: string;
  line?: number;
  /** The command as written (trimmed), for the finding's signal. */
  command: string;
  /** The file sits in a test or fixture tree: only counted findings are kept (§Q). */
  alertsOnly?: boolean;
}

/** Only these ecosystems have a registry client; the others are OSV-only and not in scope. */
const IN_SCOPE: ReadonlySet<PackageEcosystem> = new Set<PackageEcosystem>(['npm', 'PyPI']);

// A command line in a doc that is an obvious example: the names in it are nobody's package.
const EXAMPLE_RE =
  /<[^<>\s]+>|\byour[-_]|\bmy[-_](?!sql\b|py\b)|\bexample[-_]|[-_]example\b|@myorg\/|@my-org\/|@repo\/|\bpackage\d\b|\bpkg[-_]?name\b|\bfoo\b|\bbar\b|\bxxx\b/i;

// The runners and installers a doc line has to start with (after `$`, `sudo`, `cd x &&`) to be
// read as a command: prose that mentions "pip" is not one.
const RUNNER_RE =
  /\b(?:npx|bunx|pnpx|uvx|pipx|pip3?|npm|pnpm|yarn|bun|uv|python3?\s+-m\s+pip)\s+\S/;

function refsFromCommand(
  command: string,
  base: Omit<PackageRef, 'ecosystem' | 'name' | 'version' | 'manager' | 'command'>
): PackageRef[] {
  let reqs;
  try {
    reqs = extractPackageInstalls(command);
  } catch {
    return [];
  }
  const out: PackageRef[] = [];
  for (const r of reqs) {
    if (!IN_SCOPE.has(r.ecosystem)) continue;
    out.push({
      ...base,
      ecosystem: r.ecosystem,
      name: r.name,
      ...(r.version ? { version: r.version } : {}),
      manager: r.manager,
      command: command.trim().slice(0, 200),
    });
  }
  return out;
}

const quoteArg = (a: string) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`);

interface ServerSpec {
  command?: unknown;
  args?: unknown;
  disabled?: unknown;
  enabled?: unknown;
}

function serverArgv(spec: ServerSpec): string[] {
  if (Array.isArray(spec.command)) return spec.command.map(String); // opencode
  if (typeof spec.command !== 'string') return [];
  const args = Array.isArray(spec.args) ? spec.args.map(String) : [];
  return [spec.command, ...args];
}

function serverRefs(
  servers: Record<string, unknown>,
  file: string,
  content: string,
  alertsOnly: boolean
): PackageRef[] {
  const out: PackageRef[] = [];
  for (const [name, raw] of Object.entries(servers)) {
    if (!raw || typeof raw !== 'object') continue;
    const spec = raw as ServerSpec;
    if (spec.disabled === true || spec.enabled === false) continue;
    const argv = serverArgv(spec);
    if (argv.length === 0) continue;
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const at = content.search(
      new RegExp(`"${esc}"\\s*:|^[ \\t]*\\[mcp_servers\\.(?:"${esc}"|${esc})\\]`, 'm')
    );
    out.push(
      ...refsFromCommand(argv.map(quoteArg).join(' '), {
        surface: 'mcp',
        autoRun: true,
        file,
        ...(at >= 0 ? { line: lineAtIndex(content, at) } : {}),
        ...(alertsOnly ? { alertsOnly } : {}),
      })
    );
  }
  return out;
}

const obj = (x: unknown): Record<string, unknown> =>
  x && typeof x === 'object' && !Array.isArray(x) ? (x as Record<string, unknown>) : {};

/** MCP servers in a JSON config (`mcpServers`, VS Code `servers`, opencode `mcp`). */
export function mcpPackageRefs(file: string, content: string, alertsOnly = false): PackageRef[] {
  let cfg: Record<string, unknown>;
  try {
    cfg = obj(JSON.parse(content));
  } catch {
    return [];
  }
  return [cfg.mcpServers, cfg.servers, cfg.mcp].flatMap((s) =>
    serverRefs(obj(s), file, content, alertsOnly)
  );
}

/** MCP servers in a Codex `config.toml` (`[mcp_servers.<name>]`). */
export function codexPackageRefs(file: string, content: string, alertsOnly = false): PackageRef[] {
  let cfg: Record<string, unknown>;
  try {
    cfg = obj(parseToml(content));
  } catch {
    return [];
  }
  return serverRefs(obj(cfg.mcp_servers), file, content, alertsOnly);
}

/** A hook command or a folder-open task command: runs by itself. */
export function triggerPackageRefs(
  kind: 'claude-hook' | 'vscode-task',
  file: string,
  command: string,
  line: number | undefined,
  alertsOnly = false
): PackageRef[] {
  return refsFromCommand(command, {
    surface: kind === 'claude-hook' ? 'hook' : 'task',
    autoRun: true,
    file,
    ...(line ? { line } : {}),
    ...(alertsOnly ? { alertsOnly } : {}),
  });
}

const SHELL_FENCE_RE =
  /^\s*(?:```|~~~)\s*(?:(?:ba|z|da)?sh|shell|console|terminal|cmd|powershell|ps1)?\s*$/i;
const ANY_FENCE_RE = /^\s*(?:```|~~~)/;
// A Markdown block inside a doc (an example notice, a README template) is still Markdown: its
// inline code spans are read like the doc's own.
const MD_FENCE_RE = /^\s*(?:```|~~~)\s*(?:markdown|md|mdx)\s*$/i;

/** Command lines in a Markdown doc: shell code blocks (and blocks with no language), and inline
 *  code spans that start with a runner. Prose is never read as a command. */
function docCommandLines(content: string): { text: string; line: number }[] {
  const out: { text: string; line: number }[] = [];
  const lines = content.split('\n');
  let fence: 'shell' | 'markdown' | 'other' | null = null;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (ANY_FENCE_RE.test(l)) {
      if (fence) fence = null;
      else fence = SHELL_FENCE_RE.test(l) ? 'shell' : MD_FENCE_RE.test(l) ? 'markdown' : 'other';
      continue;
    }
    if (fence === 'other') continue;
    if (fence === 'shell') {
      const t = l.replace(/^\s*(?:\$|>|PS>|#)\s+/, '').replace(/\s+#\s.*$/, '');
      if (RUNNER_RE.test(t)) out.push({ text: t, line: i + 1 });
      continue;
    }
    for (const m of l.matchAll(/`([^`\n]+)`/g)) {
      const t = m[1].replace(/^\s*\$\s+/, '');
      if (RUNNER_RE.test(t) && /^\s*(?:sudo\s+)?[\w.-]+(?:\s|$)/.test(t))
        out.push({ text: t, line: i + 1 });
    }
  }
  return out;
}

const SHELL_SCRIPT_RE = /\.(?:sh|bash|zsh)$/i;

/** Text surfaces: a doc's command lines, or the lines of a shell script. Other script languages
 *  are not read (their install notes live in comments and strings). */
export function textPackageRefs(
  file: string,
  content: string,
  surface: 'doc' | 'skill-script' | 'hook-script',
  alertsOnly = false
): PackageRef[] {
  let lines: { text: string; line: number }[];
  if (surface === 'doc') lines = docCommandLines(content);
  else {
    const first = content.slice(0, 120).split('\n')[0];
    if (!SHELL_SCRIPT_RE.test(file) && !/^#!.*\b(?:ba|z|da)?sh\b/.test(first)) return [];
    lines = content
      .split('\n')
      .map((text, i) => ({ text: text.replace(/(^|\s)#.*$/, ''), line: i + 1 }))
      .filter((l) => RUNNER_RE.test(l.text));
  }
  const out: PackageRef[] = [];
  for (const { text, line } of lines) {
    if (EXAMPLE_RE.test(text)) continue;
    out.push(
      ...refsFromCommand(text, {
        surface,
        autoRun: surface === 'hook-script',
        file,
        line,
        ...(alertsOnly ? { alertsOnly } : {}),
      })
    );
  }
  return out;
}

/** The dependency names a repository declares in its root manifests (package.json
 *  dependencies of every kind, and its own name). A bin it runs through `npx X` may come
 *  from one of these under a different package name. */
export function declaredNpmNames(manifests: { path: string; content: string }[]): Set<string> {
  const out = new Set<string>();
  for (const m of manifests) {
    if (!/(^|\/)package\.json$/.test(m.path)) continue;
    let doc: Record<string, unknown>;
    try {
      doc = obj(JSON.parse(m.content));
    } catch {
      continue;
    }
    if (typeof doc.name === 'string') out.add(doc.name.toLowerCase());
    for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'])
      for (const n of Object.keys(obj(doc[k]))) out.add(n.toLowerCase());
  }
  return out;
}

/** Could a declared package provide the bin `bin`? The usual shapes: the same name, a scoped
 *  package of that name (`@dotenvx/dotenvx`), a package in the bin's own scope (`@slidev/cli`),
 *  or `<bin>-cli`. A name match only, no registry read: it can excuse a doc's `npx X`, never
 *  an MCP launch. */
export function binProvidedBy(bin: string, declared: ReadonlySet<string>): string | null {
  const b = bin.toLowerCase();
  for (const d of declared) {
    if (d === b || d.endsWith(`/${b}`) || d.startsWith(`@${b}/`) || d === `${b}-cli`) return d;
  }
  return null;
}
