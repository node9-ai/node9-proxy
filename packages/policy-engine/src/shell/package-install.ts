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
//
// Beyond npm and PyPI (node9Firewall#360): RubyGems (gem, bundle add), crates.io
// (cargo add / install), Go (go get / install / run), NuGet (dotnet add package,
// dotnet tool install, nuget install), Maven (mvn dependency:get), Packagist
// (composer require / create-project) and VS Code extensions from either
// marketplace (code, codium and their siblings, --install-extension).
import mvdanSh from 'mvdan-sh';
import { COMMAND_WRAPPERS, parseShared, resolveWordLiteral } from './index';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

/**
 * The OSV ecosystem name, verbatim: it is the index directory, the bucket path
 * of the OSV archive and the `ecosystem` of the online query at once. `VSCode`
 * covers both marketplaces (OSV files Open VSX records as
 * `VSCode:https://open-vsx.org` inside the same archive).
 */
export type PackageEcosystem =
  'npm' | 'PyPI' | 'RubyGems' | 'crates.io' | 'Go' | 'NuGet' | 'Maven' | 'Packagist' | 'VSCode';

export interface PackageInstallRequest {
  ecosystem: PackageEcosystem;
  /** The front-end that would install it: npm, pnpm, yarn, bun, npx, pip, uv, poetry … */
  manager: string;
  /** Registry name: npm as written (scope kept); PyPI per PEP 503; the others as written. */
  name: string;
  /** Exact pinned version when the spec names one; otherwise undefined. */
  version?: string;
  /** The argument as written. */
  raw: string;
  /** Literal cd steps before this call; null means the execution context is unknown. */
  localCwd?: string[] | null;
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

/**
 * The flags whose next word is their value, for a front-end by name. Shared
 * with the registry reader (package-registry.ts), so the two parsers agree
 * on where a verb is: `npm --prefix ./app install` installs.
 */
export function packageManagerValueFlags(manager: string): ReadonlySet<string> {
  switch (manager) {
    case 'npm':
    case 'npx':
      return NPM_VALUE_FLAGS;
    case 'pnpm':
    case 'pnpx':
      return PNPM_VALUE_FLAGS;
    case 'yarn':
      return YARN_VALUE_FLAGS;
    case 'bun':
    case 'bunx':
      return BUN_VALUE_FLAGS;
    case 'pip':
    case 'pip3':
      return PIP_VALUE_FLAGS;
    case 'uv':
    case 'uvx':
      return UV_VALUE_FLAGS;
    case 'pipenv':
      return PIPENV_VALUE_FLAGS;
    case 'pipx':
      return PIPX_VALUE_FLAGS;
    default:
      return new Set();
  }
}

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

/**
 * Values of the given flags (`--from X`, `--with=X`), e.g. the package uvx
 * installs. uv takes a comma-separated list there (`--with a,b`), so values
 * are split on commas; a comma never appears in a package spec.
 */
function flagValues(words: (string | null)[], from: number, names: string[]): string[] {
  const out: string[] = [];
  for (let i = from; i >= 0 && i < words.length; i++) {
    const w = words[i];
    if (w === null) continue;
    for (const n of names) {
      let v: string | undefined;
      if (w === n && typeof words[i + 1] === 'string') v = words[i + 1] as string;
      else if (w.startsWith(n + '=')) v = w.slice(n.length + 1);
      if (v !== undefined) out.push(...v.split(',').filter((x) => x.length > 0));
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

// ── Other ecosystems (node9Firewall#360) ───────────────────────────────────
// Each tool gets its own value-flag set, under the rule written above: list
// only flags that take a separate value in THAT tool. A boolean flag listed
// here would swallow the next package (a bypass); a value flag left out only
// costs one extra lookup of its value.

/**
 * A version the command pins exactly: dot-separated numbers, an optional
 * `-pre` or `+build` tail, an optional leading `v` or `=`. Anything else (a
 * range, `1.x`, `~> 1.0`, RubyGems' `1.0.pre`) is left undefined on purpose:
 * an undefined version is checked against every malicious version of the
 * name, a wrongly "exact" one against none of them.
 */
const EXACT_VERSION_RE = /^=?v?(\d+(?:\.\d+)*(?:[-+][0-9A-Za-z][0-9A-Za-z.+-]*)?)$/;
function exactVersion(v: string | undefined): string | undefined {
  if (!v) return undefined;
  const m = EXACT_VERSION_RE.exec(v.trim());
  return m ? m[1] : undefined;
}

function push(
  out: PackageInstallRequest[],
  ecosystem: PackageEcosystem,
  manager: string,
  name: string,
  version: string | undefined,
  raw: string
): void {
  out.push({ ecosystem, manager, name, ...(version ? { version } : {}), raw });
}

// Name shapes accept any Unicode letter or digit on purpose: OSV lists
// malicious NuGet packages whose ids swap Latin letters for Cyrillic look-alikes,
// and an ASCII-only shape would skip exactly those. Rejecting a name is the
// unsafe direction here; an unusual name only costs one lookup.
const GEM_NAME_RE = /^[\p{L}\p{N}][\p{L}\p{N}_.-]*$/u;
const GEM_VALUE_FLAGS = new Set([
  '-v',
  '--version',
  '-i',
  '--install-dir',
  '-n',
  '--bindir',
  '--document',
  '--build-root',
  '-P',
  '--trust-policy',
  '-s',
  '--source',
  '-p',
  '--http-proxy',
  '--platform',
  '-g',
  '--file',
  '--without',
]);
const BUNDLE_VALUE_FLAGS = new Set([
  '-v',
  '--version',
  '-g',
  '--group',
  '-s',
  '--source',
  '-r',
  '--require',
  '--path',
  '--git',
  '--github',
  '--branch',
  '--ref',
  '--glob',
]);

/** `gem install a b -v 1.0`, `gem install a:1.0`: -v applies to every name. */
function gemInstall(words: (string | null)[], from: number, out: PackageInstallRequest[]): void {
  // After `--` gem passes build flags to the extension, not more gems.
  const dash = words.indexOf('--', from);
  const own = dash < 0 ? words : words.slice(0, dash);
  const pinned = exactVersion(flagValues(own, from, ['-v', '--version'])[0]);
  for (const raw of operands(own, from, GEM_VALUE_FLAGS)) {
    if (NON_REGISTRY_RE.test(raw) || /\.gem$/i.test(raw)) continue;
    const colon = raw.indexOf(':');
    const name = colon < 0 ? raw : raw.slice(0, colon);
    if (!GEM_NAME_RE.test(name)) continue;
    push(
      out,
      'RubyGems',
      'gem',
      name,
      colon < 0 ? pinned : exactVersion(raw.slice(colon + 1)),
      raw
    );
  }
}

const CRATE_NAME_RE = /^[\p{L}\p{N}][\p{L}\p{N}_-]*$/u;
const CARGO_ADD_VALUE_FLAGS = new Set([
  '-F',
  '--features',
  '--rename',
  '--registry',
  '--manifest-path',
  '-p',
  '--package',
  '--git',
  '--branch',
  '--tag',
  '--rev',
  '--path',
  '--base',
  '--target',
  '--color',
  '--config',
  '-Z',
  '--lockfile-path',
]);
const CARGO_INSTALL_VALUE_FLAGS = new Set([
  '--version',
  '--vers',
  '--git',
  '--branch',
  '--tag',
  '--rev',
  '--path',
  '--root',
  '--index',
  '--registry',
  '-F',
  '--features',
  '--profile',
  '--target',
  '--target-dir',
  '-j',
  '--jobs',
  '--bin',
  '--example',
  '--color',
  '--config',
  '-Z',
]);

/** `cargo add name[@req]…`, `cargo install name[@ver] [--version V]`. A crate
 *  from git, a path or another registry is not a crates.io package. */
function cargoCrates(
  words: (string | null)[],
  from: number,
  manager: 'cargo add' | 'cargo install',
  out: PackageInstallRequest[]
): void {
  const flags = manager === 'cargo add' ? CARGO_ADD_VALUE_FLAGS : CARGO_INSTALL_VALUE_FLAGS;
  if (flagValues(words, from, ['--git', '--path', '--registry', '--index']).length > 0) return;
  if (words.some((w) => w === '--git' || w === '--path')) return;
  const flagVersion =
    manager === 'cargo install'
      ? exactVersion(flagValues(words, from, ['--version', '--vers'])[0])
      : undefined;
  for (const raw of operands(words, from, flags)) {
    const at = raw.indexOf('@');
    const name = at < 0 ? raw : raw.slice(0, at);
    if (!CRATE_NAME_RE.test(name)) continue;
    push(
      out,
      'crates.io',
      manager,
      name,
      at < 0 ? flagVersion : exactVersion(raw.slice(at + 1)),
      raw
    );
  }
}

const GO_VALUE_FLAGS = new Set([
  '-C',
  '-tags',
  '-ldflags',
  '-gcflags',
  '-asmflags',
  '-mod',
  '-modfile',
  '-o',
  '-p',
  '-pkgdir',
  '-toolexec',
  '-exec',
  '-overlay',
  '-pgo',
  '-buildmode',
  '-compiler',
  '-gccgoflags',
  '-installsuffix',
  '-covermode',
  '-coverpkg',
]);
/** A remote import path: its first element is a host name (has a dot). */
const GO_PATH_RE = /^[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+(?:\/[\p{L}\p{N}_.~+-]+)*$/u;

/**
 * `go get` / `go install` / `go run` operands: `path[@version]`. A local path,
 * a pattern (`./...`), a standard-library name and `@none` (a removal) are not
 * downloads. `go run` treats only its first operand as the package, and
 * downloads it only with an explicit `@version` (otherwise it builds inside the
 * current module). `@latest` and branch names leave the version unknown.
 */
function goModules(
  words: (string | null)[],
  from: number,
  manager: 'go get' | 'go install' | 'go run',
  out: PackageInstallRequest[]
): void {
  let specs = operands(words, from, GO_VALUE_FLAGS);
  if (manager === 'go run') specs = specs.slice(0, 1).filter((s) => s.includes('@'));
  for (const raw of specs) {
    const at = raw.indexOf('@');
    const pathPart = (at < 0 ? raw : raw.slice(0, at)).replace(/\/\.\.\.$/, '');
    const ver = at < 0 ? undefined : raw.slice(at + 1);
    if (ver === 'none') continue;
    if (!GO_PATH_RE.test(pathPart) || /\.go$/i.test(pathPart)) continue;
    // OSV writes Go versions without the leading v.
    const exact = ver && /^v\d/.test(ver) ? exactVersion(ver) : undefined;
    push(out, 'Go', manager, pathPart, exact, raw);
  }
}

const NUGET_NAME_RE = /^[\p{L}\p{N}_][\p{L}\p{N}_.-]*$/u;
const DOTNET_ADD_VALUE_FLAGS = new Set([
  '-v',
  '--version',
  '-s',
  '--source',
  '-f',
  '--framework',
  '--package-directory',
]);
const DOTNET_TOOL_VALUE_FLAGS = new Set([
  '--version',
  '--add-source',
  '--configfile',
  '--framework',
  '--tool-path',
  '-a',
  '--arch',
  '--tool-manifest',
  '-v',
  '--verbosity',
]);
// Lower case: nuget.exe flags are case-insensitive and nugetInstall lowers them.
const NUGET_VALUE_FLAGS = new Set([
  '-version',
  '-outputdirectory',
  '-o',
  '-source',
  '-configfile',
  '-fallbacksource',
  '-framework',
  '-packagesavemode',
  '-dependencyversion',
  '-solutiondirectory',
  '-verbosity',
]);

/** `dotnet add [PROJECT] package NAME [--version V]`. */
function dotnetAdd(words: (string | null)[], from: number, out: PackageInstallRequest[]): void {
  // The project argument is optional: `package` is the next word or the one after.
  let k = -1;
  for (let i = from; i < Math.min(words.length, from + 2); i++) {
    if (lower(words[i]) === 'package') {
      k = i;
      break;
    }
  }
  if (k < 0) return;
  const name = operands(words, k + 1, DOTNET_ADD_VALUE_FLAGS)[0];
  if (!name || !NUGET_NAME_RE.test(name)) return;
  const version = exactVersion(flagValues(words, k + 1, ['-v', '--version'])[0]);
  push(out, 'NuGet', 'dotnet add package', name, version, name);
}

/** `dotnet tool install|update [-g] NAME [--version V]`: a tool is a NuGet package. */
function dotnetTool(words: (string | null)[], from: number, out: PackageInstallRequest[]): void {
  const name = operands(words, from, DOTNET_TOOL_VALUE_FLAGS)[0];
  if (!name || !NUGET_NAME_RE.test(name)) return;
  const version = exactVersion(flagValues(words, from, ['--version'])[0]);
  push(out, 'NuGet', 'dotnet tool', name, version, name);
}

/** `nuget install NAME [-Version V]`: Windows-style flags, any case. */
function nugetInstall(words: (string | null)[], from: number, out: PackageInstallRequest[]): void {
  const lowered = words.map((w) => (w !== null && w.startsWith('-') ? w.toLowerCase() : w));
  const name = operands(lowered, from, NUGET_VALUE_FLAGS)[0];
  if (!name || !NUGET_NAME_RE.test(name) || /\.config$/i.test(name)) return;
  const version = exactVersion(flagValues(lowered, from, ['-version'])[0]);
  push(out, 'NuGet', 'nuget install', name, version, name);
}

const MAVEN_COORD_RE = /^[\p{L}\p{N}_.-]+:[\p{L}\p{N}_.-]+$/u;

/**
 * `mvn dependency:get -Dartifact=g:a:v[:packaging[:classifier]]` or the
 * `-DgroupId= -DartifactId= -Dversion=` form, also through the Maven wrapper
 * and the plugin's full name. `LATEST` and `RELEASE` leave the version unknown.
 */
function mavenGet(words: (string | null)[], from: number, out: PackageInstallRequest[]): void {
  const goal = words
    .slice(from)
    .some(
      (w) =>
        w !== null &&
        /(?:^|:)dependency:get$|^org\.apache\.maven\.plugins:maven-dependency-plugin:(?:[\w.-]+:)?get$/.test(
          w
        )
    );
  if (!goal) return;
  const prop = (key: string): string | undefined => {
    for (let i = from; i < words.length; i++) {
      const w = words[i];
      if (w === null) continue;
      if (w.startsWith(`-D${key}=`)) return w.slice(key.length + 3);
      if (w === '-D' && words[i + 1]?.startsWith(`${key}=`))
        return (words[i + 1] as string).slice(key.length + 1);
    }
    return undefined;
  };
  const artifact = prop('artifact');
  let coord: string | undefined;
  let ver: string | undefined;
  if (artifact) {
    const parts = artifact.split(':');
    if (parts.length < 2) return;
    coord = `${parts[0]}:${parts[1]}`;
    ver = parts[2];
  } else {
    const g = prop('groupId');
    const a = prop('artifactId');
    if (!g || !a) return;
    coord = `${g}:${a}`;
    ver = prop('version');
  }
  if (!MAVEN_COORD_RE.test(coord)) return;
  const exact = ver && !/^(?:LATEST|RELEASE)$/i.test(ver) ? exactVersion(ver) : undefined;
  push(out, 'Maven', 'mvn dependency:get', coord, exact, artifact ?? coord);
}

// One class per side, no nested quantifier: a shape with optional separators
// inside a repeated group backtracks exponentially on a long non-matching word.
const COMPOSER_NAME_RE = /^[\p{L}\p{N}][\p{L}\p{N}_.-]*\/[\p{L}\p{N}][\p{L}\p{N}_.-]*$/u;
const COMPOSER_VALUE_FLAGS = new Set([
  '-d',
  '--working-dir',
  '--stability',
  '--repository',
  '--add-repository',
]);

/** `composer require vendor/name[:constraint]…`, `vendor/name=constraint`,
 *  `composer create-project vendor/name [dir] [version]`. Platform packages
 *  (`php`, `ext-*`) have no vendor and are not registry packages. */
function composerPackages(
  words: (string | null)[],
  from: number,
  manager: 'composer require' | 'composer create-project',
  out: PackageInstallRequest[]
): void {
  const ops = operands(words, from, COMPOSER_VALUE_FLAGS);
  const specs = manager === 'composer create-project' ? ops.slice(0, 1) : ops;
  for (const raw of specs) {
    const sep = raw.search(/[:=]/);
    const name = sep < 0 ? raw : raw.slice(0, sep);
    if (!COMPOSER_NAME_RE.test(name)) continue;
    let ver = sep < 0 ? undefined : raw.slice(sep + 1);
    if (manager === 'composer create-project' && ver === undefined) ver = ops[2] ?? undefined;
    push(out, 'Packagist', manager, name.toLowerCase(), exactVersion(ver), raw);
  }
}

/** Editors that take `--install-extension` (VS Code and the forks on Open VSX). */
const EDITOR_HEADS = ['code', 'code-insiders', 'codium', 'vscodium', 'cursor'];
const EXTENSION_ID_RE = /^[\p{L}\p{N}][\p{L}\p{N}_-]*\.[\p{L}\p{N}][\p{L}\p{N}_.-]*$/u;

/** `code --install-extension publisher.name[@version]`, repeatable; a `.vsix`
 *  file is a local package, not a marketplace name. */
function editorExtensions(
  words: (string | null)[],
  from: number,
  out: PackageInstallRequest[]
): void {
  for (const raw of flagValues(words, from, ['--install-extension'])) {
    if (/\.vsix$/i.test(raw) || NON_REGISTRY_RE.test(raw)) continue;
    const at = raw.lastIndexOf('@');
    const name = at <= 0 ? raw : raw.slice(0, at);
    if (!EXTENSION_ID_RE.test(name)) continue;
    push(
      out,
      'VSCode',
      'code --install-extension',
      name,
      at <= 0 ? undefined : exactVersion(raw.slice(at + 1)),
      raw
    );
  }
}

// ── Command walk ────────────────────────────────────────────────────────────

function basename(w: string | null): string {
  return (w ?? '').toLowerCase().split('/').pop() ?? '';
}

const MANAGER_HEADS = new Set([
  'gem',
  'bundle',
  'cargo',
  'go',
  'dotnet',
  'nuget',
  'mvn',
  'mvnw',
  'composer',
  ...EDITOR_HEADS,
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
        if (w === null || !/^[-+]/.test(w)) break;
        // Shell options that take a separate value before -c (`+o`/`+O` unset).
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

  // Versioned front-ends behave like the bare name: python3.12, pip3.11.
  const family = /^python\d+(?:\.\d+)*$/.test(head)
    ? 'python'
    : /^pip\d+(?:\.\d+)*$/.test(head)
      ? 'pip'
      : head;
  switch (family) {
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
    case 'gem': {
      const v = verbIndex(words, start + 1, GEM_VALUE_FLAGS);
      if (v >= 0 && ['install', 'i'].includes(lower(words[v]))) gemInstall(words, v + 1, out);
      return;
    }
    case 'bundle': {
      const v = verbIndex(words, start + 1, BUNDLE_VALUE_FLAGS);
      if (v < 0 || lower(words[v]) !== 'add') return;
      if (flagValues(words, v + 1, ['--git', '--github', '--path']).length > 0) return;
      const version = exactVersion(flagValues(words, v + 1, ['-v', '--version'])[0]);
      for (const raw of operands(words, v + 1, BUNDLE_VALUE_FLAGS))
        if (GEM_NAME_RE.test(raw)) push(out, 'RubyGems', 'bundle add', raw, version, raw);
      return;
    }
    case 'cargo': {
      // `cargo +nightly add x`: a toolchain override comes before the verb.
      const from = words[start + 1]?.startsWith('+') ? start + 2 : start + 1;
      const v = verbIndex(words, from, CARGO_ADD_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (verb === 'add') cargoCrates(words, v + 1, 'cargo add', out);
      else if (verb === 'install') cargoCrates(words, v + 1, 'cargo install', out);
      return;
    }
    case 'go': {
      const v = verbIndex(words, start + 1, GO_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (verb === 'get' || verb === 'install' || verb === 'run')
        goModules(words, v + 1, `go ${verb}`, out);
      return;
    }
    case 'dotnet': {
      const v = verbIndex(words, start + 1, DOTNET_ADD_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (verb === 'add') dotnetAdd(words, v + 1, out);
      else if (verb === 'tool' && ['install', 'update'].includes(lower(words[v + 1])))
        dotnetTool(words, v + 2, out);
      return;
    }
    case 'nuget': {
      if (lower(words[start + 1]) === 'install') nugetInstall(words, start + 2, out);
      return;
    }
    case 'mvn':
    case 'mvnw':
      mavenGet(words, start + 1, out);
      return;
    case 'composer': {
      let v = verbIndex(words, start + 1, COMPOSER_VALUE_FLAGS);
      if (v >= 0 && lower(words[v]) === 'global') v = verbIndex(words, v + 1, COMPOSER_VALUE_FLAGS);
      const verb = lower(words[v]);
      if (verb === 'require' || verb === 'req' || verb === 'r')
        composerPackages(words, v + 1, 'composer require', out);
      else if (verb === 'create-project')
        composerPackages(words, v + 1, 'composer create-project', out);
      return;
    }
    default:
      if (EDITOR_HEADS.includes(family)) editorExtensions(words, start + 1, out);
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

// Only a simple call, optionally preceded by literal `cd ... &&` steps, can
// prove which local tree will be used. Other shell structures still extract
// every package, but must not take the local-only shortcut.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function localContexts(file: any): Map<number, string[]> {
  const contexts = new Map<number, string[]>();
  // mvdan-sh uses numeric operators; derive && from the parser rather than
  // duplicating its internal enum.
  const sample = parseShared('cd . && true');
  if (typeof sample === 'symbol') return contexts;
  const andOp = sample.Stmts[0].Cmd.Op;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function visit(stmt: any, steps: string[], depth = 0): string[] | null {
    if (depth > 64) return null;
    if (!stmt || stmt.Background || stmt.Negated || stmt.Redirs?.length) return null;
    const cmd = stmt.Cmd;
    const kind = syntax.NodeType(cmd);
    if (kind === 'BinaryCmd' && cmd.Op === andOp) {
      const next = visit(cmd.X, steps, depth + 1);
      return next === null ? null : visit(cmd.Y, next, depth + 1);
    }
    if (kind !== 'CallExpr' || cmd.Assigns?.length) return null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const words = (cmd.Args ?? []).map((w: any) => resolveWordLiteral(w));
    if (
      words[0] === 'cd' &&
      words.length === 2 &&
      typeof words[1] === 'string' &&
      words[1] &&
      !/^[-~]/.test(words[1])
    )
      return [...steps, words[1]];
    if (!['npx', 'npm', 'bunx', 'bun'].includes(words[0])) return null;
    // Context-changing flags, wrappers and expansions cannot prove locality.
    if (
      words.some(
        (w: string | null) =>
          w === null ||
          /^(?:--(?:prefix|cwd|directory|workspace|workspaces|global|ignore-existing)(?:=|$)|-[Cwg])/.test(
            w
          )
      )
    )
      return null;
    contexts.set(cmd.Pos().Offset(), steps);
    // An arbitrary executable can mutate node_modules before the next call.
    return null;
  }
  if (file.Stmts?.length === 1) visit(file.Stmts[0], []);
  return contexts;
}

function collect(command: string, out: PackageInstallRequest[], depth: number): void {
  if (!command || command.length > 50_000) return;
  const f = parseShared(command);
  if (typeof f === 'symbol') return;
  const contexts = depth === 0 ? localContexts(f) : new Map<number, string[]>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  syntax.Walk(f, (node: any) => {
    if (node && syntax.NodeType(node) === 'CallExpr') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const words = ((node.Args as any[]) || []).map((a) => resolveWordLiteral(a));
      const start = out.length;
      if (words.length > 0) fromCall(words, out, depth);
      const steps = contexts.get(node.Pos().Offset());
      for (let i = start; i < out.length; i++) {
        if (['npx', 'bunx', 'npm exec'].includes(out[i].manager)) {
          if (!steps) out[i].localCwd = null;
          else if (steps.length) out[i].localCwd = steps;
        }
      }
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
  // Deduplicate only equivalent requests: a local run never hides a download.
  const seen = new Set<string>();
  return out.filter((r) => {
    const k = JSON.stringify([r.ecosystem, r.manager, r.name, r.raw, r.localCwd]);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
