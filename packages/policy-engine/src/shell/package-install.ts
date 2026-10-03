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

// ── Flags that take a value ─────────────────────────────────────────────────
// Per front-end: the flags whose NEXT word is their value, not a package.
// Listing a flag that is boolean in that tool would swallow the package after
// it (`pnpm add -w evil`: -w is boolean in pnpm) — a silent bypass — so each
// set holds only flags that take a value in THAT tool. An unlisted value flag
// errs the other way: its value is looked up as a package name too, which
// costs a lookup and blocks nothing that is not itself in the index.
const NPM_VALUE_FLAGS = new Set([
  '--registry',
  '--prefix',
  '--cache',
  '--userconfig',
  '--globalconfig',
  '--workspace',
  '-w',
  '--loglevel',
  '--tag',
  '--before',
  '--omit',
  '--include',
  '--install-strategy',
  '--save-prefix',
  '--scope',
  '--otp',
  '--cpu',
  '--os',
  '--libc',
]);
const PNPM_VALUE_FLAGS = new Set([
  '--registry',
  '-C',
  '--dir',
  '--filter',
  '-F',
  '--store-dir',
  '--virtual-store-dir',
  '--modules-dir',
  '--lockfile-dir',
  '--loglevel',
  '--reporter',
  '--network-concurrency',
  '--child-concurrency',
  '--workspace-concurrency',
]);
const YARN_VALUE_FLAGS = new Set([
  '--registry',
  '--cwd',
  '--modules-folder',
  '--cache-folder',
  '--global-folder',
  '--link-folder',
  '--preferred-cache-folder',
  '--mutex',
  '--network-timeout',
  '--network-concurrency',
  '--use-yarnrc',
  '--otp',
]);
const BUN_VALUE_FLAGS = new Set([
  '--registry',
  '--cwd',
  '--cache-dir',
  '-c',
  '--config',
  '--omit',
  '--backend',
]);
const PIP_VALUE_FLAGS = new Set([
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
  '-e',
  '--editable',
  '--platform',
  '--python-version',
  '--implementation',
  '--abi',
  '--proxy',
  '--cache-dir',
  '--log',
  '--trusted-host',
  '--upgrade-strategy',
  '--progress-bar',
  '--report',
  '-C',
  '--config-settings',
  '--global-option',
  '--no-binary',
  '--only-binary',
  '--retries',
  '--timeout',
  '--exists-action',
  '--cert',
  '--client-cert',
  '--python',
]);
const UV_VALUE_FLAGS = new Set([
  '-p',
  '--python',
  '--group',
  '--optional',
  '--index',
  '--index-url',
  '--default-index',
  '--extra-index-url',
  '-f',
  '--find-links',
  '--with',
  '--from',
  '--directory',
  '--project',
  '--package',
  '--rev',
  '--tag',
  '--branch',
  '--extra',
  '--config-file',
  '--cache-dir',
  '-r',
  '--requirement',
  '-c',
  '--constraint',
  '-e',
  '--editable',
  '--target',
  '--prefix',
  '--index-strategy',
  '--keyring-provider',
  '--resolution',
  '--prerelease',
  '--exclude-newer',
  '--link-mode',
  '--color',
  '-m',
  '--marker',
  '--bounds',
  '--script',
]);
const POETRY_VALUE_FLAGS = new Set([
  '-G',
  '--group',
  '--source',
  '-E',
  '--extras',
  '--python',
  '--platform',
  '-C',
  '--directory',
  '-P',
  '--project',
]);
const PIPENV_VALUE_FLAGS = new Set([
  '-r',
  '--requirements',
  '--python',
  '-i',
  '--index',
  '--extra-index-url',
  '--categories',
  '-e',
  '--editable',
]);
const PIPX_VALUE_FLAGS = new Set([
  '--python',
  '--pip-args',
  '--index-url',
  '--spec',
  '--suffix',
  '--preinstall',
]);

/** Is `w` a value-taking flag (and not already `--flag=value`)? */
function takesValue(w: string, valueFlags: Set<string>): boolean {
  return !w.includes('=') && valueFlags.has(w);
}

/** Index of the first non-flag word at or after `from`, skipping flag values; -1 if none or dynamic. */
function verbIndex(words: (string | null)[], from: number, valueFlags: Set<string>): number {
  for (let i = from; i < words.length; i++) {
    const w = words[i];
    if (w === null) return -1;
    if (w.startsWith('-')) {
      if (takesValue(w, valueFlags)) i++;
      continue;
    }
    return i;
  }
  return -1;
}

/** Non-flag operands after `from`, honouring value-taking flags. */
function operands(words: (string | null)[], from: number, valueFlags: Set<string>): string[] {
  const out: string[] = [];
  if (from < 0) return out;
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
      if (takesValue(w, valueFlags)) i++;
      continue;
    }
    out.push(w);
  }
  return out;
}

/** Values of the given flags (`--from X`, `--with=X`), e.g. the package uvx installs. */
function flagValues(words: (string | null)[], from: number, names: string[]): string[] {
  const out: string[] = [];
  for (let i = from; i >= 0 && i < words.length; i++) {
    const w = words[i];
    if (w === null) continue;
    for (const n of names) {
      if (w === n && typeof words[i + 1] === 'string') out.push(words[i + 1] as string);
      else if (w.startsWith(n + '=')) out.push(w.slice(n.length + 1));
    }
  }
  return out;
}

// ── PyPI ────────────────────────────────────────────────────────────────────
// PEP 508 name, optional extras, optional version specifier.
const PY_SPEC_RE = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?\s*(.*)$/;
const PY_EXACT_RE = /^===?\s*v?(\d+(?:\.\d+)*(?:[a-zA-Z0-9.+!-]*))$/;
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

const MANAGER_HEADS = new Set([
  'npm',
  'npx',
  'pnpm',
  'yarn',
  'bun',
  'bunx',
  'pip',
  'pip3',
  'pipx',
  'python',
  'python3',
  'py',
  'uv',
  'uvx',
  'poetry',
  'pipenv',
]);
// Shells whose `-c` argument is a script we re-read (`bash -lc "npm i x"`).
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash']);
const MAX_NESTING = 3;
const SHELL_VALUE_FLAGS = new Set(['--rcfile', '--init-file', '-O', '+O', '-o', '+o']);

/**
 * Skip `sudo -u bob`, `env FOO=1`, `nice -n 5`, `timeout 30` … and return the
 * head index. A wrapper flag's following word is taken as that flag's value
 * unless it is itself a package manager, a shell or another wrapper — so
 * `sudo -u deploy npm i x` reaches npm instead of stopping at `deploy`.
 */
function skipWrappers(words: (string | null)[]): number {
  let i = 0;
  while (i < words.length) {
    const head = basename(words[i]);
    if (!COMMAND_WRAPPERS.has(head)) break;
    i++;
    while (i < words.length) {
      const t = words[i];
      if (t === null) return i;
      if (/^[A-Za-z_]\w*=/.test(t) || /^\d+(?:\.\d+)?[smhd]?$/.test(t)) {
        i++;
        continue;
      }
      if (t.startsWith('-')) {
        i++;
        const next = words[i];
        const nb = basename(next ?? null);
        if (
          next != null &&
          !next.startsWith('-') &&
          !MANAGER_HEADS.has(nb) &&
          !SHELLS.has(nb) &&
          !COMMAND_WRAPPERS.has(nb)
        )
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

/** `npx [flags] [-p pkg]… <pkg|cmd> [args]`: the packages npx would fetch. */
function npxPackages(words: (string | null)[], from: number): string[] {
  const explicit = flagValues(words, from, ['-p', '--package']);
  for (let i = from; i >= 0 && i < words.length; i++) {
    const w = words[i];
    if (w === null) return explicit; // dynamic — the command is unknowable
    if (w === '--') {
      const next = words[i + 1];
      return explicit.length > 0 ? explicit : next ? [next] : [];
    }
    if (w.startsWith('-')) {
      // -p/--package values were collected above; -c/--call takes a shell string.
      if (w === '-p' || w === '--package' || w === '-c' || w === '--call') i++;
      else if (takesValue(w, NPM_VALUE_FLAGS)) i++;
      continue;
    }
    // First bare operand: the package itself unless -p named the packages.
    return explicit.length > 0 ? explicit : [w];
  }
  return explicit;
}

/** uvx / `uv tool run`: the tool package, plus `--from` / `--with` packages. */
function uvxPackages(words: (string | null)[], from: number): string[] {
  const from_ = flagValues(words, from, ['--from']);
  const withs = flagValues(words, from, ['--with']);
  const first = verbIndex(words, from, UV_VALUE_FLAGS);
  const tool = first >= 0 && from_.length === 0 ? [words[first] as string] : [];
  return [...from_, ...tool, ...withs];
}

function lower(w: string | null | undefined): string {
  return (w ?? '').toLowerCase();
}

function fromCall(words: (string | null)[], out: PackageInstallRequest[], depth: number): void {
  const start = skipWrappers(words);
  const head = basename(words[start]);

  // `bash -lc "npm i x"` / `sh -c '…'` / `eval "…"`: re-read the script.
  if (depth < MAX_NESTING && (SHELLS.has(head) || head === 'eval')) {
    let script: string | null = null;
    if (head === 'eval') {
      const parts = words.slice(start + 1);
      if (parts.every((w) => w !== null)) script = parts.join(' ');
    } else {
      for (let i = start + 1; i < words.length; i++) {
        const w = words[i];
        if (w === null || !w.startsWith('-')) break;
        // Shell options that take a separate value before -c.
        if (SHELL_VALUE_FLAGS.has(w)) {
          i++;
          continue;
        }
        if (/^-[a-z]*c[a-z]*$/i.test(w) && !w.startsWith('--')) {
          script = words[i + 1] ?? null;
          break;
        }
      }
    }
    if (script) {
      collect(script, out, depth + 1);
      // The word resolver keeps `\"` escapes inside double quotes (they are
      // only dropped in the jail walk), so `bash -c "bash -c \"npm i x\""`
      // arrives with literal backslashes. Read the de-escaped script too: an
      // extra reading can only add lookups, never hide a package.
      const unescaped = script.replace(/\\(["\\$`])/g, '$1');
      if (unescaped !== script) collect(unescaped, out, depth + 1);
    }
    return;
  }

  switch (head) {
    case 'npm': {
      const v = verbIndex(words, start + 1, NPM_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (v < 0) return;
      if (NPM_INSTALL_VERBS.has(verb)) pushNpm(out, 'npm', operands(words, v + 1, NPM_VALUE_FLAGS));
      else if (NPM_EXEC_VERBS.has(verb)) pushNpm(out, 'npm exec', npxPackages(words, v + 1));
      return;
    }
    case 'npx':
      pushNpm(out, 'npx', npxPackages(words, start + 1));
      return;
    case 'pnpm': {
      const v = verbIndex(words, start + 1, PNPM_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (v < 0) return;
      if (PNPM_INSTALL_VERBS.has(verb))
        pushNpm(out, 'pnpm', operands(words, v + 1, PNPM_VALUE_FLAGS));
      else if (DLX_VERBS.has(verb)) pushNpm(out, 'pnpm dlx', npxPackages(words, v + 1));
      return;
    }
    case 'yarn': {
      let v = verbIndex(words, start + 1, YARN_VALUE_FLAGS);
      if (v < 0) return;
      // `yarn global add pkg` (v1) — step over `global`.
      if (lower(words[v]) === 'global') v = verbIndex(words, v + 1, YARN_VALUE_FLAGS);
      // `yarn workspace <name> add pkg` (v1 and berry) — step over both.
      else if (lower(words[v]) === 'workspace') {
        const name = verbIndex(words, v + 1, YARN_VALUE_FLAGS);
        v = name < 0 ? -1 : verbIndex(words, name + 1, YARN_VALUE_FLAGS);
      }
      const verb = lower(words[v]);
      if (v < 0) return;
      if (YARN_INSTALL_VERBS.has(verb))
        pushNpm(out, 'yarn', operands(words, v + 1, YARN_VALUE_FLAGS));
      else if (DLX_VERBS.has(verb)) pushNpm(out, 'yarn dlx', npxPackages(words, v + 1));
      return;
    }
    case 'bun': {
      const v = verbIndex(words, start + 1, BUN_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (v < 0) return;
      if (BUN_INSTALL_VERBS.has(verb)) pushNpm(out, 'bun', operands(words, v + 1, BUN_VALUE_FLAGS));
      else if (verb === 'x') pushNpm(out, 'bunx', npxPackages(words, v + 1));
      return;
    }
    case 'bunx':
      pushNpm(out, 'bunx', npxPackages(words, start + 1));
      return;
    case 'pip':
    case 'pip3':
      pipInstall(words, start + 1, head, out);
      return;
    case 'python':
    case 'python3':
    case 'py': {
      // python [-I -u -W ignore …] -m pip [global flags] install …
      for (let i = start + 1; i < words.length; i++) {
        const w = words[i];
        if (w === null || !w.startsWith('-')) return;
        if (w === '-W' || w === '-X' || w === '--check-hash-based-pycs') {
          i++; // interpreter flags that take a separate value
          continue;
        }
        if (w === '-m') {
          if (basename(words[i + 1] ?? null) === 'pip') pipInstall(words, i + 2, 'pip', out);
          return;
        }
      }
      return;
    }
    case 'pipx': {
      const v = verbIndex(words, start + 1, PIPX_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (v < 0) return;
      const spec = flagValues(words, v + 1, ['--spec']);
      if (verb === 'install')
        pushPy(out, 'pipx', [...spec, ...operands(words, v + 1, PIPX_VALUE_FLAGS)]);
      else if (verb === 'run')
        pushPy(
          out,
          'pipx run',
          spec.length > 0 ? spec : operands(words, v + 1, PIPX_VALUE_FLAGS),
          1
        );
      return;
    }
    case 'uv': {
      const v = verbIndex(words, start + 1, UV_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (v < 0) return;
      if (verb === 'add') {
        pushPy(out, 'uv add', operands(words, v + 1, UV_VALUE_FLAGS));
        return;
      }
      // `uv run --with pkg script.py` installs pkg into an ephemeral env.
      if (verb === 'run') {
        pushPy(out, 'uv run', flagValues(words, v + 1, ['--with', '--with-editable']));
        return;
      }
      const v2 = verbIndex(words, v + 1, UV_VALUE_FLAGS);
      const sub = lower(words[v2]);
      if (v2 < 0) return;
      if (verb === 'pip' && sub === 'install')
        pushPy(out, 'uv pip', operands(words, v2 + 1, UV_VALUE_FLAGS));
      else if (verb === 'tool' && sub === 'install')
        pushPy(out, 'uv tool', [
          ...flagValues(words, v2 + 1, ['--from', '--with']),
          ...operands(words, v2 + 1, UV_VALUE_FLAGS),
        ]);
      else if (verb === 'tool' && sub === 'run') pushPy(out, 'uvx', uvxPackages(words, v2 + 1));
      return;
    }
    case 'uvx':
      pushPy(out, 'uvx', uvxPackages(words, start + 1));
      return;
    case 'poetry': {
      const v = verbIndex(words, start + 1, POETRY_VALUE_FLAGS);
      if (v >= 0 && lower(words[v]) === 'add')
        pushPy(out, 'poetry', operands(words, v + 1, POETRY_VALUE_FLAGS));
      return;
    }
    case 'pipenv': {
      const v = verbIndex(words, start + 1, PIPENV_VALUE_FLAGS);
      if (v >= 0 && lower(words[v]) === 'install')
        pushPy(out, 'pipenv', operands(words, v + 1, PIPENV_VALUE_FLAGS));
      return;
    }
    default:
      return;
  }
}

/** `pip [global flags] install [flags] specs…` starting after the `pip` word. */
function pipInstall(
  words: (string | null)[],
  from: number,
  manager: string,
  out: PackageInstallRequest[]
): void {
  const v = verbIndex(words, from, PIP_VALUE_FLAGS);
  if (v >= 0 && lower(words[v]) === 'install')
    pushPy(out, manager, operands(words, v + 1, PIP_VALUE_FLAGS));
}

function collect(command: string, out: PackageInstallRequest[], depth: number): void {
  if (!command || command.length > 50_000) return;
  const f = parseShared(command);
  if (typeof f === 'symbol') return;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  syntax.Walk(f, (node: any) => {
    if (node && syntax.NodeType(node) === 'CallExpr') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const words = ((node.Args as any[]) || []).map((a) => resolveWordLiteral(a));
      if (words.length > 0) fromCall(words, out, depth);
    }
    return true;
  });
}

/**
 * Every registry package the command would install or run, in command order.
 * Walks every simple command in the AST (so `cd x && npm i evil | tee log`
 * still yields `evil`), and re-reads the script of `sh -c` / `bash -lc` /
 * `eval` up to three levels deep. A command that does not parse yields
 * nothing — the check fails open by construction; the policy engine's other
 * detectors keep their own fallbacks.
 */
export function extractPackageInstalls(command: string): PackageInstallRequest[] {
  const out: PackageInstallRequest[] = [];
  collect(command, out, 0);
  // Deduplicate identical (ecosystem, name, version) rows from repeated calls.
  const seen = new Set<string>();
  return out.filter((r) => {
    const k = `${r.ecosystem}\0${r.name}\0${r.version ?? ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
