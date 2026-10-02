// packages/policy-engine/src/shell/package-install.ts
// Package-install extraction from a shell command (AST-based, mvdan-sh).
//
// Answers one question: WHICH registry packages would this command install or
// run? `npm install left-pad@1.3.0`, `npx cowsay`, `pip install requests==2.31`,
// `uv add httpx`, `poetry add rich`. The host (proxy) checks the answer against
// the OSV malicious-package index before the command runs. Pure: a string in,
// a list out, no I/O, no verdict.
//
// Things that are NOT registry packages are skipped on purpose: local paths,
// tarballs, git/URL specs, `-r requirements.txt` operands. A bare `npm install`
// (install from the lockfile) yields nothing; the lockfile is out of scope here.
import mvdanSh from 'mvdan-sh';
import { COMMAND_WRAPPERS, parseShared, resolveWordLiteral } from './index';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

export type PackageEcosystem = 'npm' | 'PyPI';

export interface PackageInstallRequest {
  ecosystem: PackageEcosystem;
  /** The front-end that would install it: npm, pnpm, yarn, bun, npx, pip, uv, poetry … */
  manager: string;
  /** Registry name, normalised: npm as written (scope kept); PyPI per PEP 503. */
  name: string;
  /** Exact pinned version when the spec names one; otherwise undefined. */
  version?: string;
  /** The argument as written. */
  raw: string;
}

// ── npm-family ──────────────────────────────────────────────────────────────
const NPM_INSTALL_VERBS = new Set([
  'install',
  'i',
  'add',
  'in',
  'ins',
  'inst',
  'insta',
  'instal',
  'isnt',
  'isnta',
  'isntal',
  'isntall',
]);
const NPM_EXEC_VERBS = new Set(['exec', 'x']);
const PNPM_INSTALL_VERBS = new Set(['add', 'install', 'i']);
const YARN_INSTALL_VERBS = new Set(['add']);
const BUN_INSTALL_VERBS = new Set(['add', 'install', 'i', 'a']);
const DLX_VERBS = new Set(['dlx']);

// A spec that is not a registry package: a path, a URL, a git ref, a tarball.
const NON_REGISTRY_RE =
  /^(?:\.|\/|~|[a-z]+:\/\/|git\+|github:|gitlab:|bitbucket:|gist:|file:|link:|workspace:|[\w.-]+\/[\w.-]+#)|\.(?:tgz|tar\.gz|tar|zip|whl)$/i;
const NPM_NAME_RE = /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i;
const EXACT_SEMVER_RE = /^v?(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)$/;

/** `name`, `name@spec`, `@scope/name@spec`, `alias@npm:name@spec`. */
function parseNpmSpec(raw: string): { name: string; version?: string } | null {
  if (!raw || raw.startsWith('-') || NON_REGISTRY_RE.test(raw)) return null;
  let spec = raw;
  // alias@npm:real@1.0.0 — the registry package is the one after `npm:`
  const aliasAt = spec.indexOf('@npm:');
  if (aliasAt > 0) spec = spec.slice(aliasAt + 5);
  if (spec.startsWith('npm:')) spec = spec.slice(4);
  const at = spec.indexOf('@', 1); // skip a leading scope '@'
  const name = at > 0 ? spec.slice(0, at) : spec;
  const range = at > 0 ? spec.slice(at + 1) : '';
  if (!NPM_NAME_RE.test(name)) return null;
  // Only an exact pin is a version the checker can trust; a range or a tag is
  // resolved by the host against the registry.
  const exact = EXACT_SEMVER_RE.exec(range.replace(/^=/, ''));
  return { name, version: exact ? exact[1] : undefined };
}

// npm/pnpm/yarn/bun flags whose operand is NOT a package.
const NPM_FLAGS_WITH_OPERAND = new Set([
  '--registry',
  '--prefix',
  '--cwd',
  '--filter',
  '-C',
  '--workspace',
  '-w',
  '--tag',
  '--loglevel',
  '--cache',
  '--userconfig',
  '--modules-folder',
]);

/** Non-flag operands after `from`, honouring flags that take an operand. */
function operands(words: (string | null)[], from: number, flagsWithOperand: Set<string>): string[] {
  const out: string[] = [];
  for (let i = from; i < words.length; i++) {
    const w = words[i];
    if (w === null) continue; // dynamic — unknowable, skip
    if (w === '--') {
      for (let j = i + 1; j < words.length; j++) {
        const rest = words[j];
        if (rest !== null) out.push(rest);
      }
      break;
    }
    if (w.startsWith('-')) {
      if (flagsWithOperand.has(w) && !w.includes('=')) i++;
      continue;
    }
    out.push(w);
  }
  return out;
}

// ── PyPI ────────────────────────────────────────────────────────────────────
// PEP 508 name, optional extras, optional version specifier.
const PY_SPEC_RE = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?\s*(.*)$/;
const PY_EXACT_RE = /^===?\s*v?(\d+(?:\.\d+)*(?:[a-zA-Z0-9.+!-]*))$/;
const PIP_FLAGS_WITH_OPERAND = new Set([
  '-r',
  '--requirement',
  '-c',
  '--constraint',
  '-i',
  '--index-url',
  '--extra-index-url',
  '-f',
  '--find-links',
  '-t',
  '--target',
  '--prefix',
  '--root',
  '--src',
  '--platform',
  '--python-version',
  '--implementation',
  '--abi',
  '--proxy',
  '--cache-dir',
  '--log',
  '--trusted-host',
  '--python',
  '-p',
  '--group',
  '--optional',
  '--source',
  '-e',
  '--editable',
  '--with',
  '--from',
]);

/** PEP 503 normalisation: lowercase, runs of `-_.` collapse to `-`. */
export function normalizePyPiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

function parsePySpec(raw: string): { name: string; version?: string } | null {
  if (!raw || raw.startsWith('-') || NON_REGISTRY_RE.test(raw)) return null;
  // `pkg @ https://…` direct references are URLs, not registry packages.
  if (/\s@\s|@https?:/.test(raw)) return null;
  const m = PY_SPEC_RE.exec(raw.trim());
  if (!m) return null;
  const name = normalizePyPiName(m[1]);
  const exact = PY_EXACT_RE.exec(m[2].trim());
  return { name, version: exact ? exact[1] : undefined };
}

// ── Command walk ────────────────────────────────────────────────────────────

function basename(w: string | null): string {
  return (w ?? '').toLowerCase().split('/').pop() ?? '';
}

/** Skip `sudo`, `env FOO=1`, `nice -n 5`, `timeout 30` … and return the head index. */
function skipWrappers(words: (string | null)[]): number {
  let i = 0;
  while (i < words.length) {
    const head = basename(words[i]);
    if (!COMMAND_WRAPPERS.has(head)) break;
    i++;
    while (i < words.length) {
      const t = words[i];
      if (t === null) break;
      if (/^[A-Za-z_]\w*=/.test(t) || t.startsWith('-') || /^\d+[smhd]?$/.test(t)) {
        i++;
        continue;
      }
      break;
    }
  }
  return i;
}

function pushNpm(
  out: PackageInstallRequest[],
  manager: string,
  specs: string[],
  limit = Infinity
): void {
  let n = 0;
  for (const raw of specs) {
    if (n >= limit) break;
    const p = parseNpmSpec(raw);
    if (!p) continue;
    out.push({ ecosystem: 'npm', manager, name: p.name, version: p.version, raw });
    n++;
  }
}

function pushPy(out: PackageInstallRequest[], manager: string, specs: string[], limit = Infinity) {
  let n = 0;
  for (const raw of specs) {
    if (n >= limit) break;
    const p = parsePySpec(raw);
    if (!p) continue;
    out.push({ ecosystem: 'PyPI', manager, name: p.name, version: p.version, raw });
    n++;
  }
}

/** `npx [-y] [-p pkg]… <pkg|cmd> [args]`: the packages npx would fetch. */
function npxPackages(words: (string | null)[], from: number): string[] {
  const explicit: string[] = [];
  for (let i = from; i < words.length; i++) {
    const w = words[i];
    if (w === null) return explicit; // dynamic — stop, the command is unknowable
    if (w === '--') {
      const next = words[i + 1];
      return explicit.length > 0 ? explicit : next ? [next] : [];
    }
    if (w === '-p' || w === '--package') {
      const v = words[i + 1];
      if (v) explicit.push(v);
      i++;
      continue;
    }
    if (w.startsWith('--package=')) {
      explicit.push(w.slice('--package='.length));
      continue;
    }
    if (w.startsWith('-')) {
      if (w === '-c' || w === '--call') i++; // `npx -c "cmd"`: the operand is a shell string
      continue;
    }
    // First bare operand: the package itself unless -p named the packages.
    return explicit.length > 0 ? explicit : [w];
  }
  return explicit;
}

function fromCall(words: (string | null)[], out: PackageInstallRequest[]): void {
  const start = skipWrappers(words);
  const head = basename(words[start]);
  const sub = (words[start + 1] ?? '').toLowerCase();
  const rest = (from: number, flags = NPM_FLAGS_WITH_OPERAND) => operands(words, from, flags);

  switch (head) {
    case 'npm':
      if (NPM_INSTALL_VERBS.has(sub)) pushNpm(out, 'npm', rest(start + 2));
      else if (NPM_EXEC_VERBS.has(sub)) pushNpm(out, 'npm exec', npxPackages(words, start + 2));
      return;
    case 'npx':
      pushNpm(out, 'npx', npxPackages(words, start + 1));
      return;
    case 'pnpm':
      if (PNPM_INSTALL_VERBS.has(sub)) pushNpm(out, 'pnpm', rest(start + 2));
      else if (DLX_VERBS.has(sub)) pushNpm(out, 'pnpm dlx', npxPackages(words, start + 2));
      return;
    case 'yarn': {
      // `yarn global add pkg` (v1) — step over `global`.
      const off = sub === 'global' ? 1 : 0;
      const verb = off ? (words[start + 2] ?? '').toLowerCase() : sub;
      if (YARN_INSTALL_VERBS.has(verb)) pushNpm(out, 'yarn', rest(start + 2 + off));
      else if (DLX_VERBS.has(verb)) pushNpm(out, 'yarn dlx', npxPackages(words, start + 2 + off));
      return;
    }
    case 'bun':
      if (BUN_INSTALL_VERBS.has(sub)) pushNpm(out, 'bun', rest(start + 2));
      else if (sub === 'x') pushNpm(out, 'bunx', npxPackages(words, start + 2));
      return;
    case 'bunx':
      pushNpm(out, 'bunx', npxPackages(words, start + 1));
      return;
    case 'pip':
    case 'pip3':
    case 'pipx':
      if (sub === 'install') pushPy(out, head, rest(start + 2, PIP_FLAGS_WITH_OPERAND));
      else if (head === 'pipx' && sub === 'run')
        pushPy(out, 'pipx run', rest(start + 2, PIP_FLAGS_WITH_OPERAND), 1);
      return;
    case 'python':
    case 'python3':
    case 'py':
      // python -m pip install …
      if (sub === '-m' && basename(words[start + 2]) === 'pip') {
        if ((words[start + 3] ?? '').toLowerCase() === 'install')
          pushPy(out, 'pip', rest(start + 4, PIP_FLAGS_WITH_OPERAND));
      }
      return;
    case 'uv':
      if (sub === 'add') pushPy(out, 'uv add', rest(start + 2, PIP_FLAGS_WITH_OPERAND));
      else if (sub === 'pip' && (words[start + 2] ?? '').toLowerCase() === 'install')
        pushPy(out, 'uv pip', rest(start + 3, PIP_FLAGS_WITH_OPERAND));
      else if (sub === 'tool' && (words[start + 2] ?? '').toLowerCase() === 'install')
        pushPy(out, 'uv tool', rest(start + 3, PIP_FLAGS_WITH_OPERAND));
      else if (sub === 'tool' && (words[start + 2] ?? '').toLowerCase() === 'run')
        pushPy(out, 'uvx', rest(start + 3, PIP_FLAGS_WITH_OPERAND), 1);
      return;
    case 'uvx':
      pushPy(out, 'uvx', rest(start + 1, PIP_FLAGS_WITH_OPERAND), 1);
      return;
    case 'poetry':
      if (sub === 'add') pushPy(out, 'poetry', rest(start + 2, PIP_FLAGS_WITH_OPERAND));
      return;
    case 'pipenv':
      if (sub === 'install') pushPy(out, 'pipenv', rest(start + 2, PIP_FLAGS_WITH_OPERAND));
      return;
    default:
      return;
  }
}

/**
 * Every registry package the command would install or run, in command order.
 * Walks every simple command in the AST (so `cd x && npm i evil | tee log`
 * still yields `evil`). A command that does not parse yields nothing — the
 * check fails open by construction; the policy engine's other detectors keep
 * their own fallbacks.
 */
export function extractPackageInstalls(command: string): PackageInstallRequest[] {
  if (!command || command.length > 50_000) return [];
  const f = parseShared(command);
  if (typeof f === 'symbol') return [];
  const out: PackageInstallRequest[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  syntax.Walk(f, (node: any) => {
    if (node && syntax.NodeType(node) === 'CallExpr') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const words = ((node.Args as any[]) || []).map((a) => resolveWordLiteral(a));
      if (words.length > 0) fromCall(words, out);
    }
    return true;
  });
  // Deduplicate identical (ecosystem, name, version) rows from repeated calls.
  const seen = new Set<string>();
  return out.filter((r) => {
    const k = `${r.ecosystem}\0${r.name}\0${r.version ?? ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
