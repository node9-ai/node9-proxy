// src/ci-check/deps.ts
// fw#481 A1, PR mode (`scan-repo <dir> --base <ref>`): the registry dependencies a change ADDS to
// its manifests, so an agent-written PR that adds a package the model invented, a look-alike or a
// known malicious one is caught before merge. Only added names are looked up: auditing a
// repository's existing dependency list is what npm audit, Snyk, Socket and Dependabot do.
//
// Read: every package.json (outside dependency dirs), requirements*.txt and pyproject.toml
// ([project] dependencies and optional-dependencies, [dependency-groups], Poetry tables).
// Lockfiles are not read. Design: scanner-a1-packages-design.md §4.5.

import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { parse as parseToml } from 'smol-toml';
import { normalizePyPiName, type PackageEcosystem } from '@node9/policy-engine';
import { catFileBatch, gitEnv, GIT_SAFE, isUnwalked } from './fetch';
import { lineOf } from './lines';

export interface DeclaredDep {
  ecosystem: PackageEcosystem;
  name: string;
  /** Exact version when the spec pins one. */
  version?: string;
  file: string;
  line?: number;
  /** The entry as written, for the finding's signal. */
  spec: string;
}

export interface ManifestSet {
  deps: DeclaredDep[];
  /** Names the tree's own package.json files publish (workspace packages are not registry ones). */
  ownNames: Set<string>;
  /** A private npm registry or Python index is configured, so a public 404 proves nothing. */
  privateNpm: boolean;
  privatePy: boolean;
}

const MANIFEST_RE = /(^|\/)(package\.json|pyproject\.toml|requirements[^/]*\.txt)$/;
const NPMRC_RE = /(^|\/)\.npmrc$/;
const PIPCONF_RE = /(^|\/)(pip\.conf|pip\.ini|uv\.toml|poetry\.toml)$/;
const MAX_FILES = 400;
const MAX_BYTES = 1024 * 1024;

const EXACT_NPM_RE = /^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?)$/;
const PY_EXACT_RE = /^===?\s*v?(\d+(?:\.\d+)*(?:[a-zA-Z0-9.+!-]*))$/;
const PY_NAME_RE = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*([^;#]*)/;

const obj = (x: unknown): Record<string, unknown> =>
  x && typeof x === 'object' && !Array.isArray(x) ? (x as Record<string, unknown>) : {};

/** An npm spec that is a registry range (not a path, git, URL, workspace or tag alias). */
function npmRegistrySpec(name: string, spec: string): { name: string; version?: string } | null {
  let s = spec.trim();
  let n = name;
  const alias = /^npm:((?:@[^/@]+\/)?[^@]+)(?:@(.*))?$/.exec(s);
  if (alias) {
    n = alias[1];
    s = alias[2] ?? '';
  }
  if (/^(file:|link:|workspace:|portal:|patch:|git(\+|:)|https?:|github:|catalog:)/.test(s))
    return null;
  if (/^[\w.-]+\/[\w.-]+(#.*)?$/.test(s)) return null; // owner/repo shorthand
  const exact = EXACT_NPM_RE.exec(s);
  return { name: n, ...(exact ? { version: exact[1] } : {}) };
}

function packageJsonDeps(file: string, content: string, own: Set<string>): DeclaredDep[] {
  let doc: Record<string, unknown>;
  try {
    doc = obj(JSON.parse(content));
  } catch {
    return [];
  }
  if (typeof doc.name === 'string') own.add(doc.name.toLowerCase());
  const out: DeclaredDep[] = [];
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, spec] of Object.entries(obj(doc[k]))) {
      if (typeof spec !== 'string') continue;
      const r = npmRegistrySpec(name, spec);
      if (!r) continue;
      out.push({
        ecosystem: 'npm',
        name: r.name,
        ...(r.version ? { version: r.version } : {}),
        file,
        // Inside its own section: the same key may appear earlier (a script of that name).
        line: lineOf(content, `"${name}"`, Math.max(0, content.indexOf(`"${k}"`))),
        spec: `"${name}": "${spec}"`,
      });
    }
  }
  return out;
}

function pep508(file: string, content: string, raw: string): DeclaredDep | null {
  const t = raw.trim();
  if (!t || /^(-|\.|\/|git\+|https?:)/.test(t) || /\s@\s/.test(t)) return null; // flags, paths, URLs
  const m = PY_NAME_RE.exec(t);
  if (!m) return null;
  const exact = PY_EXACT_RE.exec(m[2].trim());
  return {
    ecosystem: 'PyPI',
    name: normalizePyPiName(m[1]),
    ...(exact ? { version: exact[1] } : {}),
    file,
    line: lineOf(content, t),
    spec: t.slice(0, 120),
  };
}

function requirementsDeps(file: string, content: string): { deps: DeclaredDep[]; index: boolean } {
  const deps: DeclaredDep[] = [];
  let index = false;
  for (const line of content.split('\n')) {
    const t = line.replace(/\s+#.*$/, '').trim();
    if (/^(--index-url|-i|--extra-index-url)\b/.test(t)) index = true;
    if (!t || t.startsWith('#') || t.startsWith('-')) continue;
    const d = pep508(file, content, t);
    if (d) deps.push(d);
  }
  return { deps, index };
}

function pyprojectDeps(file: string, content: string): { deps: DeclaredDep[]; index: boolean } {
  let doc: Record<string, unknown>;
  try {
    doc = obj(parseToml(content));
  } catch {
    return { deps: [], index: false };
  }
  const specs: string[] = [];
  const project = obj(doc.project);
  for (const s of Array.isArray(project.dependencies) ? project.dependencies : [])
    if (typeof s === 'string') specs.push(s);
  for (const list of Object.values(obj(project['optional-dependencies'])))
    for (const s of Array.isArray(list) ? list : []) if (typeof s === 'string') specs.push(s);
  for (const list of Object.values(obj(doc['dependency-groups'])))
    for (const s of Array.isArray(list) ? list : []) if (typeof s === 'string') specs.push(s);
  const deps = specs.map((s) => pep508(file, content, s)).filter((d): d is DeclaredDep => !!d);
  // Poetry: `name = "^1.2"` or `name = { version = "…" }`; path/git/url tables are not registry.
  const tool = obj(doc.tool);
  const poetry = obj(tool.poetry);
  const tables = [obj(poetry.dependencies), obj(poetry['dev-dependencies'])];
  for (const g of Object.values(obj(poetry.group))) tables.push(obj(obj(g).dependencies));
  for (const t of tables)
    for (const [name, v] of Object.entries(t)) {
      if (name.toLowerCase() === 'python') continue;
      const spec = typeof v === 'string' ? v : obj(v).version;
      if (typeof spec !== 'string' && Object.keys(obj(v)).some((k) => /^(path|git|url)$/.test(k)))
        continue;
      const exact =
        typeof spec === 'string' ? /^=?=?\s*(\d+(?:\.\d+)*\S*)$/.exec(spec.trim()) : null;
      deps.push({
        ecosystem: 'PyPI',
        name: normalizePyPiName(name),
        ...(exact ? { version: exact[1] } : {}),
        file,
        line: lineOf(content, name),
        spec: `${name} = ${typeof spec === 'string' ? JSON.stringify(spec) : '{…}'}`,
      });
    }
  const index =
    Array.isArray(obj(tool.uv).index) ||
    typeof obj(tool.uv)['index-url'] === 'string' ||
    Array.isArray(poetry.source);
  return { deps, index };
}

/** Parse a set of files (path → content) into the declared dependencies. */
export function manifestSetOf(files: Map<string, string>): ManifestSet {
  const set: ManifestSet = { deps: [], ownNames: new Set(), privateNpm: false, privatePy: false };
  for (const [file, content] of files) {
    if (NPMRC_RE.test(file)) {
      if (/^\s*(@[^:\s]+:)?registry\s*=/m.test(content)) set.privateNpm = true;
      continue;
    }
    if (PIPCONF_RE.test(file)) {
      if (/index-url|\[\[index\]\]|\[\[tool\.uv\.index\]\]/.test(content)) set.privatePy = true;
      continue;
    }
    const base = path.posix.basename(file);
    if (base === 'package.json') set.deps.push(...packageJsonDeps(file, content, set.ownNames));
    else if (base === 'pyproject.toml') {
      const r = pyprojectDeps(file, content);
      set.deps.push(...r.deps);
      set.privatePy ||= r.index;
    } else {
      const r = requirementsDeps(file, content);
      set.deps.push(...r.deps);
      set.privatePy ||= r.index;
    }
  }
  return set;
}

const wanted = (p: string) =>
  !isUnwalked(p) && (MANIFEST_RE.test(p) || NPMRC_RE.test(p) || PIPCONF_RE.test(p));

function git(root: string, args: string[]): string | null {
  try {
    return execFileSync('git', [...GIT_SAFE, '-C', root, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      env: gitEnv(),
      maxBuffer: 64 * 1024 * 1024,
      timeout: 60_000,
    });
  } catch {
    return null;
  }
}

/** The manifests in the working tree (tracked or new, not ignored). Null when not a git tree. */
export function readWorkingManifests(dir: string): Map<string, string> | null {
  const list = git(dir, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']);
  if (list === null) return null;
  const out = new Map<string, string>();
  for (const p of [...new Set(list.split('\0'))]
    .filter(Boolean)
    .filter(wanted)
    .slice(0, MAX_FILES)) {
    try {
      const full = path.join(dir, p);
      const st = fs.lstatSync(full);
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      out.set(p, fs.readFileSync(full, 'utf8'));
    } catch {
      /* deleted in the working tree: not declared */
    }
  }
  return out;
}

/** The manifests at a git ref. Null when the ref cannot be read. */
export function readRefManifests(dir: string, ref: string): Map<string, string> | null {
  if (!ref || ref.startsWith('-')) return null;
  const sha = git(dir, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`])?.trim();
  if (!sha) return null;
  const listing = git(dir, ['ls-tree', '-r', '-l', '-z', sha]);
  if (listing === null) return null;
  const blobs: [string, string][] = [];
  for (const line of listing.split('\0')) {
    const tab = line.indexOf('\t');
    if (tab < 0) continue;
    const [, type, objSha, size] = line.slice(0, tab).split(/\s+/);
    const p = line.slice(tab + 1);
    if (type !== 'blob' || !wanted(p) || Number(size) > MAX_BYTES) continue;
    blobs.push([p, objSha]);
  }
  const picked = blobs.slice(0, MAX_FILES);
  let text: Map<string, string>;
  try {
    text = catFileBatch(dir, [...new Set(picked.map(([, s]) => s))]);
  } catch {
    return null;
  }
  return new Map(picked.map(([p, s]) => [p, text.get(s) ?? '']));
}

/** Dependencies in `head` whose (ecosystem, name) no manifest in `base` declares, minus the
 *  tree's own workspace packages. One entry per name (the first place it is added). */
export function addedDeps(base: ManifestSet, head: ManifestSet): DeclaredDep[] {
  const key = (d: Pick<DeclaredDep, 'ecosystem' | 'name'>) =>
    `${d.ecosystem}:${d.ecosystem === 'npm' ? d.name.toLowerCase() : d.name}`;
  const before = new Set(base.deps.map(key));
  const seen = new Set<string>();
  const out: DeclaredDep[] = [];
  for (const d of head.deps) {
    const k = key(d);
    if (before.has(k) || seen.has(k)) continue;
    if (d.ecosystem === 'npm' && head.ownNames.has(d.name.toLowerCase())) continue;
    seen.add(k);
    out.push(d);
  }
  return out;
}
