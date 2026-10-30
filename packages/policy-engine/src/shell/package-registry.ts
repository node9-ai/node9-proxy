// packages/policy-engine/src/shell/package-registry.ts
// The package registries an install command names on its own command line
// (node9Firewall#415 item 4).
//
// `npm install --registry https://<host> <pkg>` takes the package, and the
// install scripts it runs, from that host instead of the registry the user
// set up. The same for the PyPI front-ends (`pip install -i`, `--index-url`,
// `--extra-index-url`, `uv --index`, `--default-index`) and the environment
// variables each tool reads (`npm_config_registry=… npm i`,
// `PIP_INDEX_URL=… pip install`). This module only names the hosts; whether a
// host is one the user configured is the host's question (policy/index.ts,
// `isConfiguredRegistry`).
//
// Pure: a string in, a list out. Variables assigned earlier in the same
// command resolve (`R=https://x; npm i --registry "$R" p`); a value that stays
// dynamic is skipped, since nothing can be said about it.

import mvdanSh from 'mvdan-sh';
import {
  baseWord,
  literalShellPayload,
  resolveWordLiteral,
  unwrapCommandHead,
  walkCommandScope,
} from './index';
import { packageManagerValueFlags } from './package-install';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

export interface RegistryOverride {
  /** The front-end: npm, pnpm, yarn, bun, npx, pip, uv, pipx, pipenv. */
  manager: string;
  /** The flag or variable that named it, for the reason. */
  via: string;
  /** The URL as written. */
  url: string;
  /** Its host, lowercased, without the port. */
  host: string;
}

const NPM_FAMILY = new Set(['npm', 'pnpm', 'yarn', 'bun', 'npx', 'pnpx', 'bunx']);
const PIP_FAMILY = new Set(['pip', 'pip3', 'uv', 'uvx', 'pipx', 'pipenv']);
/** npm-family verbs that fetch packages (install, run from the registry, update). */
const NPM_FETCH_VERBS = new Set([
  'install',
  'i',
  'in',
  'ins',
  'inst',
  'insta',
  'instal',
  'isnt',
  'isnta',
  'isntal',
  'isntall',
  'add',
  'a',
  'ci',
  'clean-install',
  'install-clean',
  'it',
  'cit',
  'install-test',
  'update',
  'up',
  'upgrade',
  'exec',
  'x',
  'dlx',
  'create',
  'init',
]);
/** pip-family verbs that fetch packages. */
const PIP_FETCH_VERBS = new Set([
  'install',
  'download',
  'wheel',
  'add',
  'sync',
  'lock',
  'run',
  'update',
  'upgrade',
]);
const NPM_FLAGS = new Set(['--registry']);
const PIP_FLAGS = new Set([
  '-i',
  '--index-url',
  '--extra-index-url',
  '--index',
  '--default-index',
  '-f',
  '--find-links',
]);
/** The variables each family reads its registry from. */
const NPM_VARS =
  /^(?:npm_config_registry|NPM_CONFIG_REGISTRY|YARN_REGISTRY|YARN_NPM_REGISTRY_SERVER|BUN_CONFIG_REGISTRY)$/;
const PIP_VARS =
  /^(?:PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|PIP_FIND_LINKS|UV_INDEX_URL|UV_EXTRA_INDEX_URL|UV_INDEX|UV_DEFAULT_INDEX|PIPENV_PYPI_MIRROR)$/;
// Narrow on purpose: `rm -f` and `index.js` must not wake the walk.
const PRESCREEN_RE =
  /--registry|index-url|--index\b|--default-index|find-links|\s-[if]\s|npm_config_registry|_REGISTRY|PIP_|UV_(?:INDEX|DEFAULT)|PIPENV_PYPI/i;
const MAX_PAYLOAD_DEPTH = 4;

/**
 * The registries every install reaches with no configuration, and the
 * machine itself (a local registry such as Verdaccio is the user's own).
 * test.pypi.org is left out on purpose: anyone can publish any name there,
 * which is how a dependency-confusion install is staged.
 */
const PUBLIC_REGISTRY_HOSTS = new Set([
  'registry.npmjs.org',
  'registry.npmjs.com',
  'registry.yarnpkg.com',
  'pypi.org',
  'pypi.python.org',
  'files.pythonhosted.org',
]);

export function isPublicRegistryHost(host: string): boolean {
  const h = host.toLowerCase();
  return (
    PUBLIC_REGISTRY_HOSTS.has(h) ||
    h === 'localhost' ||
    h.endsWith('.localhost') ||
    h === '::1' ||
    /^127(?:\.\d{1,3}){3}$/.test(h)
  );
}

/** The host of an http(s) URL, or null. A `name=url` uv index keeps its URL. */
export function registryHost(value: string): string | null {
  const url =
    value.includes('=') && !/^https?:/i.test(value) ? value.slice(value.indexOf('=') + 1) : value;
  const m = /^https?:\/\/(?:[^@/\s]*@)?(\[[^\]]+\]|[^/:?#\s]+)/i.exec(url.trim());
  return m ? m[1].toLowerCase().replace(/^\[|\]$/g, '') : null;
}

export function extractRegistryOverrides(command: string): RegistryOverride[] {
  if (!PRESCREEN_RE.test(command)) return [];
  const out: RegistryOverride[] = [];
  collect(command, out, 0);
  const seen = new Set<string>();
  return out.filter((o) => {
    const key = `${o.manager}\u0000${o.via}\u0000${o.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function collect(command: string, out: RegistryOverride[], depth: number): void {
  try {
    walkCommandScope(command, (node: unknown) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (!n || syntax.NodeType(n) !== 'CallExpr') return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const words: (string | null)[] = ((n.Args || []) as any[]).map((a) => resolveWordLiteral(a));
      if (words.length === 0) return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const prefix: Array<[string, string | null]> = ((n.Assigns || []) as any[])
        .filter((a) => a?.Name?.Value)
        .map(
          (a) =>
            [a.Name.Value, a.Value ? resolveWordLiteral(a.Value) : ''] as [string, string | null]
        );
      fromCall(words, prefix, out);
      if (depth < MAX_PAYLOAD_DEPTH) {
        const payload = literalShellPayload(words, baseWord(words[0]));
        if (payload !== null) collect(payload, out, depth + 1);
      }
      return true;
    });
  } catch {
    // An unparsable command names no registry we can read.
  }
}

function fromCall(
  words: (string | null)[],
  prefix: Array<[string, string | null]>,
  out: RegistryOverride[]
): void {
  // The manager is the nearest family word at or before the head: the head
  // finder reads `npx` and `uv run` as runners and steps past them, and a
  // wrapper's own operand before it (`sudo -u npm npm i`) is not the manager.
  const head = Math.min(unwrapCommandHead(words), words.length - 1);
  const isManager = (w: string | null) =>
    NPM_FAMILY.has(baseWord(w)) ||
    PIP_FAMILY.has(baseWord(w)) ||
    /^python[0-9.]*$/.test(baseWord(w));
  let at = -1;
  for (let i = head; i >= 0; i--) {
    if (isManager(words[i])) {
      at = i;
      break;
    }
  }
  if (at < 0) return;
  // `env K=V npm …`: the wrapper's assignments apply to the call.
  const env = [...prefix];
  for (let i = 0; i < at; i++) {
    const m = words[i] === null ? null : /^([A-Za-z_]\w*)=(.*)$/s.exec(words[i] as string);
    if (m) env.push([m[1], m[2]]);
  }
  let manager = baseWord(words[at]);
  // `python -m pip install …`
  if (/^python[0-9.]*$/.test(manager)) {
    if (words[at + 1] !== '-m' || baseWord(words[at + 2]) !== 'pip') return;
    manager = 'pip';
    at += 2;
  }
  const npm = NPM_FAMILY.has(manager);
  const flags = npm ? NPM_FLAGS : PIP_FLAGS;
  const rest = words.slice(at + 1);
  // Every flag that takes a value, the registry ones and the manager's own
  // (`--prefix DIR`, `-w WS`), so a value is never read as the verb.
  const valued = new Set([...flags, ...packageManagerValueFlags(manager)]);
  if (!fetches(manager, rest, valued)) return;
  const vars = npm ? NPM_VARS : PIP_VARS;
  for (const [name, value] of env) {
    if (value !== null && vars.test(name)) push(out, manager, name, value);
  }
  for (let i = 0; i < runnerEnd(manager, rest, valued); i++) {
    const w = rest[i];
    if (w === null) continue;
    const eq = w.indexOf('=');
    const flag = eq > 0 && w.startsWith('--') ? w.slice(0, eq) : w;
    if (!flags.has(flag)) continue;
    const value = eq > 0 && w.startsWith('--') ? w.slice(eq + 1) : rest[++i];
    if (value !== null && value !== undefined) push(out, manager, flag, value);
  }
}

/**
 * Where the manager's own options end. A runner (`npx`, `uvx`, `pnpm dlx`,
 * `npm exec`) hands every word after the package to the package:
 * `npx create-app my-app --registry X` passes `--registry` to the generator.
 */
function runnerEnd(manager: string, rest: (string | null)[], flags: Set<string>): number {
  const runner = ['npx', 'pnpx', 'bunx', 'uvx'].includes(manager);
  let verb: string | null = null;
  for (let i = 0; i < rest.length; i++) {
    const w = rest[i];
    if (w === '--') return i;
    if (w !== null && w.startsWith('-')) {
      if (flags.has(w)) i++; // its value
      continue;
    }
    // A runner's first operand is the package; after `exec` / `x` / `dlx`,
    // the second one is.
    if (runner) return i;
    if (verb === null) verb = w;
    else if (['exec', 'x', 'dlx'].includes(verb)) return i;
  }
  return rest.length;
}

/** Does this call fetch packages? Read from its verb, the first operand. */
function fetches(manager: string, rest: (string | null)[], flags: Set<string>): boolean {
  // npx / pnpx / bunx / uvx fetch by themselves.
  if (['npx', 'pnpx', 'bunx', 'uvx'].includes(manager)) return true;
  const verbs = NPM_FAMILY.has(manager) ? NPM_FETCH_VERBS : PIP_FETCH_VERBS;
  const operands: (string | null)[] = [];
  for (let i = 0; i < rest.length && operands.length < 2; i++) {
    const w = rest[i];
    if (w !== null && w.startsWith('-')) {
      if (flags.has(w)) i++; // its value
      continue;
    }
    operands.push(w);
  }
  // A bare `yarn` installs from the lockfile.
  if (operands.length === 0) return manager === 'yarn';
  const [verb, next] = operands;
  if (verb === null) return false;
  // `uv pip install`, `uv tool install`: the namespace, then the verb.
  if ((verb === 'pip' || verb === 'tool') && PIP_FAMILY.has(manager)) {
    return next !== null && next !== undefined && verbs.has(next);
  }
  return verbs.has(verb);
}

function push(out: RegistryOverride[], manager: string, via: string, value: string): void {
  // A space-separated list (`PIP_EXTRA_INDEX_URL="a b"`) names each URL.
  for (const url of value.split(/\s+/).filter(Boolean)) {
    const host = registryHost(url);
    if (host) out.push({ manager, via, url, host });
  }
}
