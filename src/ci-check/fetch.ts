// src/ci-check/fetch.ts
// Fetch the agent-surface files of a repo — either a GitHub URL (via the
// Contents API, no clone) or a local path. CONFIG ONLY: we fetch a fixed set of
// config files, never source, and never execute anything. Every network failure
// degrades to a note (fail-open) so a rate-limit or missing dir never throws.

import fs from 'fs';
import path from 'path';
import { execFileSync } from 'node:child_process';
import { request } from 'undici';
import type { RepoTree, RepoFile } from './types';
import {
  isInstructionFile,
  isSkillSupportFile,
  skillDirsOf,
  appSkillDirsOf,
  isHookScript,
  isSkillScript,
} from './instructions';

// gh-CLI token is resolved at most once per process (spawning gh is expensive).
let cachedGhToken: string | null | undefined;

/** A GitHub token to lift the 60/hr unauthenticated limit to 5000/hr. Prefers an
 *  explicit env var; otherwise falls back to the `gh` CLI's stored credentials so
 *  a developer with `gh auth login` gets working scans with zero setup. The token
 *  is read via execFileSync (args array, NO shell) and is NEVER logged or put in
 *  an error/command string. */
export function resolveGitHubToken(): string | undefined {
  const env = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (env) return env;
  if (cachedGhToken === undefined) {
    try {
      cachedGhToken =
        execFileSync('gh', ['auth', 'token'], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
          timeout: 3000,
        }).trim() || null;
    } catch {
      cachedGhToken = null; // gh missing / not authed → stay unauthenticated
    }
  }
  return cachedGhToken ?? undefined;
}

/** The committed files that make up the agent-security surface. Fixed list —
 *  we never fetch arbitrary repo content. Workflows are enumerated separately. */
export const SURFACE_FILES = [
  // The team's suppressions. Root only; parsed by scanTree, never routed to an analyzer.
  '.node9-ignore.json',
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.mcp.json',
  '.cursor/mcp.json',
  '.codex/config.toml',
  // CI-6: agent instruction files (auto-loaded into the agent's system prompt).
  'CLAUDE.md',
  'AGENTS.md',
  'GEMINI.md',
  '.cursorrules',
  '.github/copilot-instructions.md',
  '.windsurfrules',
  '.clinerules',
];

const WORKFLOW_DIR = '.github/workflows';

// 1c-B: the instruction-file + config surface, matchable at ANY depth (a monorepo keeps its
// agent surface in sub-packages: `packages/api/CLAUDE.md`, `apps/web/.claude/settings.json`).
// Workflows are NOT here — `.github/workflows` is only valid at the repo root (enumerated
// separately). Mirrors the dispatch regexes in index.ts so anything discovered is analyzed.
// Instruction files come from the ONE definition in instructions.ts; only the config shapes
// are spelled here. Adding a surface type means one edit, and the dispatcher sees it too.
const CONFIG_FILE_RE =
  /(^|\/)\.claude\/settings(\.local)?\.json$|(^|\/)\.mcp\.json$|(^|\/)\.cursor\/mcp\.json$|(^|\/)\.codex\/config\.toml$/;
/** Every agent-surface path in a tree, entry points and configs first and a skill's
 *  supporting files last, so a cap never drops a SKILL.md to make room for its own
 *  reference docs. The ONE selector: the GitHub Trees path, the local walk and the git-ref
 *  reader all call it, so a head scan and a base scan see the same shapes and a CI-5 diff
 *  never reports an old supporting file as new. Callers pass paths already filtered for
 *  ignored directories. */
export function selectSurface(paths: string[]): string[] {
  const skillDirs = skillDirsOf(paths);
  // An application that carries a SKILL.md at its root contributes only its skill layout.
  const appDirs = appSkillDirsOf(paths, skillDirs);
  const isSupport = (p: string) => isSkillSupportFile(p, skillDirs, appDirs);
  // Scripts sort with the supporting files: a cap must never drop a SKILL.md for its own
  // helper, and a hook's settings.json before the hook it names.
  const isLate = (p: string) => isSupport(p) || isHookScript(p) || isSkillScript(p, skillDirs);
  return paths
    .filter(
      (p) =>
        isInstructionFile(p, skillDirs, appDirs) ||
        CONFIG_FILE_RE.test(p) ||
        isHookScript(p) ||
        isSkillScript(p, skillDirs)
    )
    .sort((a, b) => Number(isLate(a)) - Number(isLate(b)));
}
// Dependency / framework-output dirs that are NEVER a repo's own agent surface — a vendored
// `node_modules/**/CLAUDE.md` is noise. Skipped SILENTLY.
const IGNORE_HARD = /(^|\/)(node_modules|vendor|\.git|\.next|\.venv|site-packages)\//;
// Build-output dirs — USUALLY generated, occasionally a real source package. Skipped from
// findings (avoid stale-generated-copy noise), but a surface file found here is NOTED (not
// silently dropped) so a genuinely-committed config isn't invisible. ([7])
const IGNORE_SOFT = /(^|\/)(dist|build|out|target)\//;
/** How many NESTED surface files one reader may take. Only the GitHub API reader is capped: it
 *  pays one rate-limited request per file. The local and git readers are not — there is no
 *  total budget any more (§K, 2026-09-27): a 32 MiB budget cut real repositories (github/gh-aw
 *  commits 48.7 MB of workflows) and let padding crowd out the workflows. Memory is bounded per
 *  file instead, by MAX_FILE_BYTES and by reading content only when it is analyzed. */
export interface SurfaceCaps {
  files: number;
}
export const API_CAPS: SurfaceCaps = { files: 200 };

/** A single surface file larger than this is not read, and the scan says so. The largest real
 *  surface file across 118 repositories was 1.05 MB (2026-09-27). */
export const MAX_FILE_BYTES = 4 * 1024 * 1024;
/** The OS resolves at most ~40 symlink hops; an agent loading a file gets the same answer. */
const MAX_LINK_HOPS = 40;

/** Pure: from a flat list of repo file paths, pick the agent-surface files at any depth,
 *  skipping dependency/build dirs, capped at MAX_SURFACE_FILES. Pushes a note (marked
 *  INCOMPLETE so `scanTree` flips `incomplete`) if the tree was truncated or the cap was hit —
 *  a large monorepo must never be silently under-scanned. A surface file under a build-output
 *  dir is excluded but NOTED (not silently dropped). Shared by the GitHub Trees path and local
 *  recursion. */
export function pickSurfacePaths(
  paths: string[],
  truncated: boolean,
  notes: string[],
  caps: SurfaceCaps = API_CAPS
): string[] {
  const surface = selectSurface(paths.filter((p) => !IGNORE_HARD.test(p)));
  const matched = surface.filter((p) => !IGNORE_SOFT.test(p));
  const softSkipped = surface.filter((p) => IGNORE_SOFT.test(p));
  const capped = matched.slice(0, caps.files);
  // AT the cap, not past it: a scan that stops exactly at the limit cannot be told apart
  // from one that had more to read, so it is not reported as whole.
  if (truncated || matched.length >= caps.files) {
    notes.push(
      `repo tree is large/truncated — some agent-surface files may be INCOMPLETE (scanned ${capped.length} of ${matched.length}${truncated ? '+' : ''}).`
    );
  }
  if (softSkipped.length) {
    // NB: deliberately NO "INCOMPLETE" marker — skipping build output is intentional, not a
    // partial scan; we just surface it so a real committed config there isn't invisible.
    notes.push(
      `skipped ${softSkipped.length} agent-surface file(s) under a build-output dir (dist/build/out/target), e.g. ${softSkipped.slice(0, 3).join(', ')} — if any is a real committed config, move it out of the build dir to have it scanned.`
    );
  }
  return capped;
}

export interface ParsedRepo {
  owner: string;
  repo: string;
}

/** Progress callback — best-effort UX only (a spinner in the CLI). */
export type OnProgress = (p: { phase: string; done: number; total: number }) => void;

/** Run async tasks with a small concurrency cap so a many-workflow repo fetches
 *  in parallel (not one serial round-trip at a time) without hammering the API. */
async function pooled<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Accept github.com/owner/repo, https://…, owner/repo, with optional .git /
 *  /tree/<ref>. Returns null if it doesn't look like a GitHub ref. */
export function parseRepoUrl(input: string): ParsedRepo | null {
  let s = input.trim();
  s = s.replace(/^https?:\/\//, '').replace(/^github\.com\//, '');
  s = s.replace(/\.git$/, '').replace(/\/(tree|blob)\/.*$/, '');
  const parts = s.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const [owner, repo] = parts;
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) return null;
  return { owner, repo };
}

/** True when the input points at something on disk rather than a GitHub ref. */
export function isLocalPath(input: string): boolean {
  if (input.startsWith('.') || input.startsWith('/') || input.startsWith('~')) return true;
  try {
    return fs.existsSync(input) && fs.statSync(input).isDirectory();
  } catch {
    return false;
  }
}

function ghHeaders(): Record<string, string> {
  const h: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'node9-scan-repo',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  // Token (env or gh CLI) lifts the 60/hr unauthenticated limit to 5000/hr.
  const tok = resolveGitHubToken();
  if (tok) h.Authorization = `Bearer ${tok}`;
  return h;
}

interface ContentsFile {
  type: string;
  name: string;
  path: string;
  content?: string;
  encoding?: string;
}

async function ghGet(url: string): Promise<{ status: number; json: unknown }> {
  // Bound each request so a hung connection can't hang the command (or spin the
  // spinner) forever — critical in CI. status 0 = network error/timeout; callers
  // treat it as "couldn't fetch" (a note), so one slow file never aborts the batch.
  let res;
  try {
    res = await request(url, {
      headers: ghHeaders(),
      headersTimeout: 10_000,
      bodyTimeout: 10_000,
    });
  } catch {
    return { status: 0, json: null };
  }
  const body = await res.body.text().catch(() => '');
  let json: unknown = null;
  try {
    json = JSON.parse(body);
  } catch {
    /* non-JSON (e.g. rate-limit HTML) → leave null */
  }
  return { status: res.statusCode, json };
}

const RATE_LIMIT_NOTE =
  'GitHub rate limit hit — results may be INCOMPLETE (a missing file could be unread, not absent). Set GITHUB_TOKEN or run `gh auth login`.';
const NETWORK_NOTE =
  'A network error/timeout occurred — results may be INCOMPLETE (some files were not fetched).';

/** Fetch one file's decoded content, or null if absent. On a 403 (rate limit)
 *  we can't distinguish absent from unread, so we record a note so a partial
 *  scan is never mistaken for a clean one. */
async function fetchOne(
  owner: string,
  repo: string,
  filePath: string,
  notes: string[]
): Promise<RepoFile | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`;
  const { status, json } = await ghGet(url);
  if (status === 403 || status === 429) {
    if (!notes.includes(RATE_LIMIT_NOTE)) notes.push(RATE_LIMIT_NOTE);
    return null;
  }
  if (status === 0) {
    if (!notes.includes(NETWORK_NOTE)) notes.push(NETWORK_NOTE);
    return null;
  }
  if (status !== 200 || !json || typeof json !== 'object') return null;
  const f = json as ContentsFile;
  if (f.type !== 'file' || typeof f.content !== 'string') return null;
  const content = Buffer.from(f.content, (f.encoding as BufferEncoding) || 'base64').toString(
    'utf8'
  );
  return { path: filePath, content };
}

async function listWorkflowPaths(owner: string, repo: string, notes: string[]): Promise<string[]> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${WORKFLOW_DIR}`;
  const { status, json } = await ghGet(url);
  if (status === 403 || status === 429) {
    if (!notes.includes(RATE_LIMIT_NOTE)) notes.push(RATE_LIMIT_NOTE);
    return [];
  }
  if (status !== 200 || !Array.isArray(json)) return [];
  return (json as ContentsFile[])
    .filter((e) => e.type === 'file' && /\.ya?ml$/.test(e.name))
    .map((e) => e.path);
}

// ─────────────────────────────────────────────────────────────────────────────
// ONE reading layer (§K). Every reader produces the same listing shape, hands it to the same
// plan, applies the same symlink rule and the same per-file limit. They differ only in HOW a
// listing and a byte are obtained: the working tree, a git object, or the GitHub API. A CI-5
// diff compares a head read one way with a base read another, so any other difference between
// the readers becomes a false "introduced" finding.
// ─────────────────────────────────────────────────────────────────────────────

// ROOT-only workflow yaml (GitHub ignores nested `.github/workflows`).
const ROOT_WORKFLOW_RE = /^\.github\/workflows\/[^/]+\.ya?ml$/;

// ─────────────────────────────────────────────────────────────────────────────
// ONE reading layer (§K, corrected in §K.2). The truth is what the AGENT loads: for a working
// tree that is the disk, with links resolved the way the OS resolves them. Every reader
// produces the same raw listing (nothing followed), and ONE resolver, ONE expansion of
// directory links and ONE plan run over it. The readers differ only in HOW a listing and a
// byte are obtained: the disk, a git object, or the GitHub API. A CI-5 diff compares a head
// read one way with a base read another, so any other difference becomes a false
// "introduced" finding.
// ─────────────────────────────────────────────────────────────────────────────

type Kind = 'file' | 'link' | 'dir' | 'other';

/** Kind from a git mode (`git ls-tree`, the Trees API). */
function kindOfMode(mode: string): Kind {
  if (mode === '120000') return 'link';
  if (mode === '100644' || mode === '100755') return 'file';
  // 040000 a tree; 160000 a submodule: a directory whose content is another repository and is
  // not listed — the same as the working tree reader, which does not enter a nested repository.
  if (mode === '040000' || mode === '160000') return 'dir';
  return 'other';
}

const INCOMPLETE = 'may be INCOMPLETE';

/** One text form for every reader: a checkout written with `eol=crlf` has CRLF where the blob
 *  has LF (hermes-agent's install.ps1), and every check reads line by line. Without this, the
 *  local and git readers disagree on content that is the same file. Content only — a link's
 *  text is used exactly as stored. */
const lf = (t: string): string => t.replace(/\r\n/g, '\n');
const tooLargeNote = (rel: string) =>
  `${rel} is larger than ${MAX_FILE_BYTES / (1024 * 1024)} MiB — not read; results ${INCOMPLETE}.`;
const outsideNote = (rel: string) =>
  `${rel} is a symlink that points outside the repository — not read.`;
const unwalkedNote = (rel: string) =>
  `${rel} is a symlink into a dependency directory (node_modules, vendor, …) that is not scanned — not read.`;
const unreadNote = (rel: string, why: string) =>
  `${rel} could not be read (${why}) — results ${INCOMPLETE}.`;

/** Dependency dirs (IGNORE_HARD) are never walked on disk — a real node_modules can hold
 *  hundreds of thousands of files — so NO reader lists them: a path there is unknown to every
 *  reader alike. A check must treat such a path as unknown, never as "missing". */
export const isUnwalked = (p: string): boolean => IGNORE_HARD.test(p);

/** A reader's raw listing: every entry as stored, no link followed. */
interface Listing {
  /** Non-directory entry paths (files, links, others), sorted. */
  paths: string[];
  /** The kind at a path; directories are implicit in git and the API. */
  kind(p: string): Kind | undefined;
  /** A link's exact text; `undefined` = not fetched yet (the API), `null` = unreadable. */
  linkText(p: string): string | null | undefined;
  /** Non-directory entries anywhere under `dir`. */
  under(dir: string): string[];
}

function makeListing(
  kinds: Map<string, Kind>,
  linkText: (p: string) => string | null | undefined
): Listing {
  const paths = [...kinds.keys()].filter((p) => kinds.get(p) !== 'dir').sort();
  const dirs = new Set<string>();
  for (const [p, k] of kinds) if (k === 'dir') dirs.add(p);
  for (const p of paths)
    for (let i = p.indexOf('/'); i > 0; i = p.indexOf('/', i + 1)) dirs.add(p.slice(0, i));
  const firstAtOrAfter = (s: string) => {
    let lo = 0;
    let hi = paths.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (paths[mid] < s) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  return {
    paths,
    kind: (p) => kinds.get(p) ?? (dirs.has(p) ? 'dir' : undefined),
    linkText,
    under: (dir) => {
      const prefix = `${dir}/`;
      const out: string[] = [];
      for (let i = firstAtOrAfter(prefix); i < paths.length && paths[i].startsWith(prefix); i++)
        out.push(paths[i]);
      return out;
    },
  };
}

type Resolved =
  { real: string; kind: Kind } | { skip: 'outside' | 'dangling' | 'unwalked' } | { need: string };

/** The ONE resolver: the path walk `open(2)` does, over the listing. Component by component; a
 *  link component is replaced by its EXACT text (no trimming, no separator rewriting) relative
 *  to the directory it sits in; `..` pops one REAL component; an absolute text or a pop past the
 *  root leaves the repository; a non-directory followed by more components is ENOTDIR; more
 *  than MAX_LINK_HOPS link expansions is ELOOP. Never touches the host filesystem, so every
 *  reader gets the same answer. `need` = a link text the caller has not fetched yet. */
function resolvePath(p: string, l: Listing): Resolved {
  const real: string[] = [];
  let rest = p.split('/');
  let hops = 0;
  while (rest.length) {
    const c = rest.shift()!;
    if (c === '' || c === '.') continue;
    if (c === '..') {
      if (!real.length) return { skip: 'outside' };
      real.pop();
      continue;
    }
    const cand = real.length ? `${real.join('/')}/${c}` : c;
    const k = l.kind(cand);
    if (k === undefined) return { skip: isUnwalked(`${cand}/`) ? 'unwalked' : 'dangling' };
    if (k === 'link') {
      if (++hops > MAX_LINK_HOPS) return { skip: 'dangling' }; // ELOOP
      const t = l.linkText(cand);
      if (t === undefined) return { need: cand };
      if (t === null || t === '') return { skip: 'dangling' };
      if (t.startsWith('/')) return { skip: 'outside' };
      rest = [...t.split('/'), ...rest];
      continue;
    }
    if (k !== 'dir' && rest.length) return { skip: 'dangling' }; // ENOTDIR
    real.push(c);
  }
  const r = real.join('/');
  return { real: r, kind: r === '' ? 'dir' : l.kind(r)! };
}

/** Directory links bring their target's entries under the link's own path: an agent opening
 *  `.claude/settings.json` through `.claude -> cfg` gets `cfg/settings.json`. 109 of the 122
 *  directory links across 118 repositories sit in agent-surface positions
 *  (`.claude/skills/X -> .agents/skills/X`). A link to its own ancestor is not expanded (an
 *  agent does not recurse through it); past MAX_EXPANDED entries the scan says INCOMPLETE. */
const MAX_EXPANDED = 20_000; // measured maximum across 118 repositories: 173

function visiblePaths(
  l: Listing,
  notes: string[]
): { paths: string[]; complete: boolean } | { need: string[] } {
  const out = [...l.paths];
  const needs = new Set<string>();
  const queue = l.paths.filter((p) => l.kind(p) === 'link');
  let expanded = 0;
  let complete = true;
  for (let i = 0; i < queue.length && complete; i++) {
    const v = queue[i];
    const r = resolvePath(v, l);
    if ('need' in r) {
      needs.add(r.need);
      continue;
    }
    if (!('real' in r) || r.kind !== 'dir') continue;
    const slash = v.lastIndexOf('/');
    const parent = resolvePath(slash < 0 ? '' : v.slice(0, slash), l);
    if (!('real' in parent)) continue;
    if (r.real === '' || parent.real === r.real || parent.real.startsWith(`${r.real}/`)) continue;
    for (const q of l.under(r.real)) {
      if (expanded >= MAX_EXPANDED) {
        complete = false;
        break;
      }
      const vq = v + q.slice(r.real.length);
      out.push(vq);
      expanded++;
      if (l.kind(q) === 'link') queue.push(vq);
    }
  }
  if (needs.size) return { need: [...needs] };
  if (!complete)
    notes.push(
      `directory symlinks expand past ${MAX_EXPANDED} entries — some agent-surface files ${INCOMPLETE}.`
    );
  return { paths: out, complete };
}

/** The ONE plan: which paths are read, in order. The fixed root surface files and the root
 *  workflows always come first; nested surface files follow, through the one selector, capped
 *  only where the reader pays per file (the API). */
function planSurface(
  paths: string[],
  notes: string[],
  opts: { nestedCap?: number; truncated?: boolean } = {}
): string[] {
  const present = new Set(paths);
  const root = SURFACE_FILES.filter((p) => present.has(p));
  const workflows = paths.filter((p) => ROOT_WORKFLOW_RE.test(p));
  const nested = pickSurfacePaths(paths, !!opts.truncated, notes, {
    files: opts.nestedCap ?? Number.POSITIVE_INFINITY,
  });
  return [...new Set([...root, ...workflows, ...nested])];
}

interface PlannedRead {
  /** The path the agent opens (a link's own path when read through a link). */
  rel: string;
  /** The listing entry that holds the bytes. */
  real: string;
}

/** Listing → visible paths → plan → one read per real file. A link to a file that is already
 *  read under its own name is not read again (every real in-repo file link measured had that
 *  shape); a link to a file NOT otherwise read is read under the link's path — the agent loads
 *  it. Every skip that could hide content is said. */
function planReads(
  l: Listing,
  opts: { nestedCap?: number; truncated?: boolean } = {}
):
  | { reads: PlannedRead[]; paths: string[]; complete: boolean; notes: string[] }
  | { need: string[] } {
  const notes: string[] = [];
  const v = visiblePaths(l, notes);
  if ('need' in v) return v;
  const planned = planSurface(v.paths, notes, opts);
  const plannedSet = new Set(planned);
  const needs = new Set<string>();
  const reads: PlannedRead[] = [];
  const taken = new Set<string>();
  const dangling: string[] = [];
  for (const rel of planned) {
    const r = resolvePath(rel, l);
    if ('need' in r) {
      needs.add(r.need);
      continue;
    }
    if ('skip' in r) {
      if (r.skip === 'outside') notes.push(outsideNote(rel));
      else if (r.skip === 'unwalked') notes.push(unwalkedNote(rel));
      else dangling.push(rel);
      continue;
    }
    if (r.kind !== 'file') continue; // a directory or a submodule named like a surface file
    if (r.real !== rel && plannedSet.has(r.real)) continue; // read under its own name
    if (taken.has(r.real)) continue; // two links to one file: read once
    taken.add(r.real);
    reads.push({ rel, real: r.real });
  }
  if (needs.size) return { need: [...needs] };
  if (dangling.length)
    notes.push(
      `${dangling.length} agent-surface symlink(s) point at nothing readable (e.g. ${dangling.slice(0, 3).join(', ')}) — not read; an agent cannot load them either.`
    );
  return { reads, paths: v.paths, complete: v.complete, notes };
}

/** Compare the limit on the text every reader produces (after CRLF → LF), so a checkout written
 *  with `eol=crlf` is not over the limit where its blob is under it. */
const overLimit = (text: string) => Buffer.byteLength(text, 'utf8') > MAX_FILE_BYTES;
/** Raw bytes above this are over the limit whatever their line endings. */
const RAW_LIMIT = 2 * MAX_FILE_BYTES;

// ── local working tree ───────────────────────────────────────────────────────

// O_NONBLOCK: a FIFO swapped in after the walk must not hang the scan on open.
const OPEN_READ =
  fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);
/** Entry budget for the disk walk: the largest of 118 repositories had 123,492 (12,530 dirs,
 *  335 ms). Past it, the scan says INCOMPLETE rather than crawling on. */
const MAX_WALK_ENTRIES = 1_000_000;

/** Walk the directory as it is on disk: nothing followed, dependency dirs not entered, a nested
 *  git repository (a submodule checkout) not entered — git lists a submodule as one entry, so
 *  the base does the same. No git process: the scanned folder's own `.git/config` can run
 *  commands (`core.fsmonitor`), and a folder is scanned precisely because it is not trusted. */
function walkDisk(root: string, notes: string[]): { kinds: Map<string, Kind>; complete: boolean } {
  const kinds = new Map<string, Kind>();
  const nestedRepos: string[] = [];
  const unlistable: string[] = [];
  const stack: string[] = [''];
  let count = 0;
  let complete = true;
  while (stack.length && complete) {
    const relDir = stack.pop()!;
    let dirents: fs.Dirent[];
    try {
      dirents = fs.readdirSync(path.join(root, relDir), { withFileTypes: true });
    } catch (e) {
      unlistable.push(`${relDir || '.'} (${(e as NodeJS.ErrnoException)?.code ?? 'error'})`);
      continue;
    }
    for (const e of dirents) {
      if (++count > MAX_WALK_ENTRIES) {
        complete = false;
        break;
      }
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (isUnwalked(`${rel}/`)) continue;
        if (fs.existsSync(path.join(root, rel, '.git'))) {
          kinds.set(rel, 'dir'); // listed as a directory, not entered: git lists no content either
          nestedRepos.push(rel);
          continue;
        }
        kinds.set(rel, 'dir');
        stack.push(rel);
      } else if (e.isSymbolicLink()) kinds.set(rel, 'link');
      else if (e.isFile()) kinds.set(rel, 'file');
      else kinds.set(rel, 'other');
    }
  }
  if (!complete)
    notes.push(
      `repo is large — some agent-surface files ${INCOMPLETE} (stopped after ${MAX_WALK_ENTRIES} entries).`
    );
  if (unlistable.length)
    notes.push(
      `${unlistable.length} director${unlistable.length === 1 ? 'y' : 'ies'} could not be listed (e.g. ${unlistable.slice(0, 3).join(', ')}) — results ${INCOMPLETE}.`
    );
  if (nestedRepos.length)
    notes.push(
      `skipped ${nestedRepos.length} nested git repositor${nestedRepos.length === 1 ? 'y' : 'ies'} (e.g. ${nestedRepos.slice(0, 3).join(', ')}) — scan ${nestedRepos.length === 1 ? 'it' : 'each'} on its own.`
    );
  return { kinds, complete };
}

/** A link's text as the host OS reads it. On Windows the OS takes `\` as a separator and a
 *  drive path as absolute; the resolver speaks POSIX, so translate there and nowhere else. */
function localLinkText(root: string, rel: string): string | null {
  try {
    const t = fs.readlinkSync(path.join(root, rel));
    if (process.platform !== 'win32') return t;
    return path.win32.isAbsolute(t) ? `/${t}` : t.replace(/\\/g, '/');
  } catch {
    return null;
  }
}

/** Read one regular file through one O_NOFOLLOW handle. Throws a note-shaped error (carrying
 *  "may be INCOMPLETE") when the file cannot be read or is over the limit — the content getter
 *  runs inside scanTree's per-file guard, which records it. */
function readLocalFile(abs: string, rel: string): string {
  let fd: number | undefined;
  try {
    fd = fs.openSync(abs, OPEN_READ);
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new Error(unreadNote(rel, 'no longer a regular file'));
    if (st.size > RAW_LIMIT) throw new Error(tooLargeNote(rel));
    const text = lf(fs.readFileSync(fd, 'utf8'));
    if (overLimit(text)) throw new Error(tooLargeNote(rel));
    return text;
  } catch (e) {
    const msg = (e as Error)?.message ?? '';
    if (msg.includes(INCOMPLETE)) throw e;
    throw new Error(unreadNote(rel, (e as NodeJS.ErrnoException)?.code ?? 'error'));
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Read the agent surface of a local directory, as the agent sees it on disk. Content is NOT
 *  read here: each file is read when scanTree asks for it and then let go, so memory is bounded
 *  by one file, not by the repo. */
export function readLocalTree(dir: string): RepoTree {
  const root = dir.replace(/^~/, process.env.HOME ?? '~');
  const notes: string[] = [];
  const walked = walkDisk(root, notes);
  const plan = planReads(makeListing(walked.kinds, (p) => localLinkText(root, p)));
  if ('need' in plan) throw new Error('unreachable: local link texts are always known');
  notes.push(...plan.notes);
  const files: RepoFile[] = [];
  for (const { rel, real } of plan.reads) {
    const abs = path.join(root, real);
    let size = 0;
    try {
      size = fs.lstatSync(abs).size;
    } catch {
      /* gone since the walk: the getter reports it */
    }
    if (size > RAW_LIMIT) {
      notes.push(tooLargeNote(rel));
      continue;
    }
    files.push({
      path: rel,
      // Read on demand, not held: scanTree reads each file once, analyzes it, and moves on.
      get content(): string {
        return readLocalFile(abs, rel);
      },
    });
  }
  return {
    source: root,
    files,
    notes,
    paths: plan.paths,
    pathsComplete: walked.complete && plan.complete,
  };
}

// ── a git ref (the PR base) ──────────────────────────────────────────────────

/** git reads the repository's own config. The commands used here (rev-parse, ls-tree,
 *  cat-file) were tested not to run `core.fsmonitor` (git 2.43); these switch off the settings
 *  that run programs anyway, as a second wall. */
const GIT_SAFE = ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null'];
const gitEnv = (): NodeJS.ProcessEnv => ({
  ...process.env,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
});

/** Many blobs through ONE `git cat-file --batch` process (a process per file took 9.7 s on
 *  a 1,577-file base; one batch takes 0.12 s). Returns sha → raw text; missing objects are
 *  absent. Throws when the batch cannot be run — the caller turns that into "did not run". */
function catFileBatch(root: string, shas: string[]): Map<string, string> {
  const out = new Map<string, string>();
  if (shas.length === 0) return out;
  const buf = execFileSync('git', [...GIT_SAFE, '-C', root, 'cat-file', '--batch'], {
    input: shas.join('\n') + '\n',
    stdio: ['pipe', 'pipe', 'ignore'],
    env: gitEnv(),
    maxBuffer: 512 * 1024 * 1024,
    timeout: 120_000,
  });
  let i = 0;
  while (i < buf.length) {
    const nl = buf.indexOf(0x0a, i);
    if (nl < 0) break;
    const header = buf.toString('utf8', i, nl).split(' ');
    i = nl + 1;
    if (header[1] === 'missing' || header[1] === 'ambiguous' || header.length < 3) continue;
    const size = Number(header[2]);
    out.set(header[0], buf.toString('utf8', i, i + size));
    i += size + 1; // the content is followed by a newline
  }
  return out;
}

/** Read the agent surface as it exists at a git REF, without touching the working tree.
 *
 *  CI-5's base side: `git ls-tree -r -l` for the listing and ONE `git cat-file --batch` for the
 *  bytes — read-only plumbing, no checkout, no network. The base is the target branch, not the
 *  PR, so its size is the maintainers' own; it is read eagerly.
 *
 *  Returns `null` when the ref cannot be resolved or read (not a git repo, unknown ref, a
 *  shallow clone without the base commit). A null base is the "did-not-run" state — the caller
 *  MUST NOT treat it as an empty/clean base, which would report the whole repo as introduced. */
export function readGitRefTree(dir: string, ref: string): RepoTree | null {
  const root = dir.replace(/^~/, process.env.HOME ?? '~');
  // A ref beginning with "-" would be read by git as a flag. Reject rather than sanitize.
  if (!ref || ref.startsWith('-')) return null;
  const git = (args: string[]): string | null => {
    try {
      return execFileSync('git', [...GIT_SAFE, '-C', root, ...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        env: gitEnv(),
        maxBuffer: 256 * 1024 * 1024,
        timeout: 60_000,
      });
    } catch {
      return null;
    }
  };
  // Resolve first: this is what separates "the base could not be read" from "the base
  // genuinely had no agent surface". Only the former is did-not-run.
  const sha = git(['rev-parse', '--verify', '--quiet', `${ref}^{commit}`])?.trim();
  if (!sha) return null;
  const listing = git(['ls-tree', '-r', '-l', '-z', sha]);
  if (listing === null) return null;

  const entries = new Map<string, { kind: Kind; sha: string; size: number }>();
  for (const line of listing.split('\0')) {
    const tab = line.indexOf('\t');
    if (tab < 0) continue;
    const p = line.slice(tab + 1);
    if (isUnwalked(p)) continue; // the working tree never walks these; neither does the base
    const [mode, , objSha, size] = line.slice(0, tab).split(/\s+/);
    entries.set(p, { kind: kindOfMode(mode), sha: objSha, size: Number(size) || 0 });
  }
  try {
    // Every link's text in one batch (links are small), so resolution needs no more processes.
    const linkShas = [...entries.values()].filter((e) => e.kind === 'link').map((e) => e.sha);
    const linkText = catFileBatch(root, [...new Set(linkShas)]);
    const kinds = new Map([...entries].map(([p, e]) => [p, e.kind] as const));
    const plan = planReads(
      makeListing(kinds, (p) => {
        const e = entries.get(p);
        return e && e.kind === 'link' ? (linkText.get(e.sha) ?? null) : null;
      })
    );
    if ('need' in plan) return null; // unreachable: every link text was fetched above
    const notes = plan.notes;
    const reads = plan.reads.filter(({ rel, real }) => {
      if (entries.get(real)!.size <= RAW_LIMIT) return true;
      notes.push(tooLargeNote(rel));
      return false;
    });
    const bytes = catFileBatch(root, [...new Set(reads.map((r) => entries.get(r.real)!.sha))]);
    const files: RepoFile[] = [];
    for (const { rel, real } of reads) {
      const raw = bytes.get(entries.get(real)!.sha);
      if (raw === undefined) {
        notes.push(unreadNote(rel, 'object missing from this clone'));
        continue;
      }
      const content = lf(raw);
      if (overLimit(content)) {
        notes.push(tooLargeNote(rel));
        continue;
      }
      files.push({ path: rel, content });
    }
    return {
      source: `${root}@${ref}`,
      files,
      notes,
      paths: plan.paths,
      pathsComplete: plan.complete,
    };
  } catch {
    return null; // the base could not be read: did-not-run, never "clean"
  }
}

// ── the GitHub API ───────────────────────────────────────────────────────────

interface TreeEntry {
  path: string;
  mode: string;
  type: string;
  sha: string;
  size?: number;
}

/** The whole repository listing in ONE recursive Trees call (`HEAD` resolves directly).
 *  null on a fetch failure, so the caller falls back to the fixed root list. Never throws. */
async function listTree(
  owner: string,
  repo: string,
  notes: string[]
): Promise<{ entries: TreeEntry[]; truncated: boolean } | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`;
  const { status, json } = await ghGet(url);
  if (status === 403 || status === 429) {
    if (!notes.includes(RATE_LIMIT_NOTE)) notes.push(RATE_LIMIT_NOTE);
    return null;
  }
  if (status === 0) {
    if (!notes.includes(NETWORK_NOTE)) notes.push(NETWORK_NOTE);
    return null;
  }
  if (status !== 200 || !json || typeof json !== 'object') return null;
  const tree = json as { tree?: Partial<TreeEntry>[]; truncated?: boolean };
  if (!Array.isArray(tree.tree)) return null;
  const entries = tree.tree.filter(
    (e): e is TreeEntry =>
      (e.type === 'blob' || e.type === 'commit') &&
      typeof e.path === 'string' &&
      typeof e.sha === 'string' &&
      typeof e.mode === 'string'
  );
  return { entries, truncated: !!tree.truncated };
}

/** One scan's spend on the API. The hosted scan shares one token across every user, and a repo
 *  is free to be hostile: 2,000 workflows sharing one 4 MiB blob cost the attacker 4 MiB. So
 *  blobs are fetched once per sha, and the scan stops at a request and byte budget — above the
 *  largest real surface measured (github/gh-aw: 772 workflows, 48.7 MB) — and says so. */
export const API_BUDGET = { requests: 1000, bytes: 64 * 1024 * 1024 };

type BlobResult = { text: string } | { error: string };

class ApiSession {
  requests = 1; // the Trees call
  bytes = 0;
  budgetHit = false;
  readonly failed: string[] = [];
  private readonly cache = new Map<string, Promise<BlobResult>>();
  constructor(
    private readonly owner: string,
    private readonly repo: string,
    private readonly notes: string[]
  ) {}

  blob(sha: string, size: number): Promise<BlobResult> {
    const hit = this.cache.get(sha);
    if (hit) return hit;
    if (this.requests >= API_BUDGET.requests || this.bytes + size > API_BUDGET.bytes) {
      this.budgetHit = true;
      return Promise.resolve({ error: 'budget' });
    }
    this.requests++;
    this.bytes += size;
    const p = fetchBlob(this.owner, this.repo, sha, this.notes);
    this.cache.set(sha, p);
    return p;
  }

  /** The notes that make a partial API read visible. */
  closingNotes(): string[] {
    const out: string[] = [];
    if (this.failed.length)
      out.push(
        `${this.failed.length} file(s) could not be fetched from GitHub (e.g. ${this.failed.slice(0, 3).join(', ')}) — results ${INCOMPLETE}.`
      );
    if (this.budgetHit)
      out.push(
        `the scan stopped at its GitHub budget (${API_BUDGET.requests} requests, ${API_BUDGET.bytes / (1024 * 1024)} MiB) — results ${INCOMPLETE}.`
      );
    return out;
  }
}

/** One blob by sha — the Git Blobs API, not Contents: Contents returns a file over 1 MB with an
 *  EMPTY body (hermes-agent's 1,077,327-byte llms-full.md read as nothing) and a symlink with
 *  no content at all. Blobs returns both. Raw text: a link's text is used exactly as stored. */
async function fetchBlob(
  owner: string,
  repo: string,
  sha: string,
  notes: string[]
): Promise<BlobResult> {
  const { status, json } = await ghGet(
    `https://api.github.com/repos/${owner}/${repo}/git/blobs/${sha}`
  );
  if (status === 403 || status === 429) {
    if (!notes.includes(RATE_LIMIT_NOTE)) notes.push(RATE_LIMIT_NOTE);
    return { error: 'rate limit' };
  }
  if (status === 0) {
    if (!notes.includes(NETWORK_NOTE)) notes.push(NETWORK_NOTE);
    return { error: 'network' };
  }
  if (status !== 200 || !json || typeof json !== 'object') return { error: `HTTP ${status}` };
  const b = json as { content?: unknown; encoding?: unknown };
  if (typeof b.content !== 'string') return { error: 'malformed blob' };
  return {
    text: b.encoding === 'base64' ? Buffer.from(b.content, 'base64').toString('utf8') : b.content,
  };
}

const FETCH_CONCURRENCY = 8;

/** Fetch the agent-surface of a GitHub repo. Never throws — network/absence failures become
 *  notes; the checks run over whatever we got. The same resolver, expansion, plan and per-file
 *  limit as the local and git readers; nested files capped at API_CAPS and the whole scan at
 *  API_BUDGET, because each file costs a request. */
export async function fetchGitHubTree(
  owner: string,
  repo: string,
  onProgress?: OnProgress
): Promise<RepoTree> {
  const notes: string[] = [];
  try {
    onProgress?.({ phase: 'discovering agent surface', done: 0, total: 1 });
    const listed = await listTree(owner, repo, notes);
    if (!listed) {
      // Trees failed: fall back to the fixed root list + the workflows directory (Contents
      // API), so a scan can never look at LESS than the old root-only baseline.
      const workflowPaths = await listWorkflowPaths(owner, repo, notes);
      const allPaths = [...new Set([...SURFACE_FILES, ...workflowPaths])];
      const fetched = await pooled(allPaths, FETCH_CONCURRENCY, (p) =>
        fetchOne(owner, repo, p, notes)
      );
      return {
        source: `${owner}/${repo}`,
        files: fetched.filter((f): f is RepoFile => !!f),
        notes,
      };
    }
    const entries = new Map(
      listed.entries.filter((e) => !isUnwalked(e.path)).map((e) => [e.path, e])
    );
    const kinds = new Map(
      [...entries].map(([p, e]) => [p, e.type === 'blob' ? kindOfMode(e.mode) : 'dir'] as const)
    );
    const session = new ApiSession(owner, repo, notes);
    // Link texts are fetched as the resolver asks for them, a round per link depth.
    const linkText = new Map<string, string | null>();
    const listing = makeListing(kinds, (p) => (linkText.has(p) ? linkText.get(p)! : undefined));
    const opts = { nestedCap: API_CAPS.files, truncated: listed.truncated };
    let plan = planReads(listing, opts);
    while ('need' in plan) {
      await pooled(plan.need, FETCH_CONCURRENCY, async (p) => {
        const e = entries.get(p)!;
        const r = await session.blob(e.sha, e.size ?? 0);
        if ('text' in r) linkText.set(p, r.text);
        else {
          linkText.set(p, null);
          if (r.error !== 'budget') session.failed.push(`${p}: ${r.error}`);
        }
      });
      plan = planReads(listing, opts);
    }
    notes.push(...plan.notes);

    const reads = plan.reads.filter(({ rel, real }) => {
      if ((entries.get(real)!.size ?? 0) <= RAW_LIMIT) return true;
      notes.push(tooLargeNote(rel));
      return false;
    });
    let done = 0;
    const fetched = await pooled(reads, FETCH_CONCURRENCY, async ({ rel, real }) => {
      const e = entries.get(real)!;
      const r = await session.blob(e.sha, e.size ?? 0);
      onProgress?.({ phase: 'fetching agent surface', done: ++done, total: reads.length });
      if ('error' in r) {
        if (r.error !== 'budget') session.failed.push(`${rel}: ${r.error}`);
        return null;
      }
      const content = lf(r.text);
      if (overLimit(content)) {
        notes.push(tooLargeNote(rel));
        return null;
      }
      return { path: rel, content };
    });
    notes.push(...session.closingNotes());
    return {
      source: `${owner}/${repo}`,
      files: fetched.filter((f): f is RepoFile => !!f),
      notes,
      paths: plan.paths,
      pathsComplete: !listed.truncated && plan.complete,
    };
  } catch (err) {
    // "may be INCOMPLETE" is load-bearing — index.ts keys `incomplete` off it, so a total
    // fetch failure is never rendered as a clean bill of health.
    notes.push(
      `fetch degraded: ${(err as Error)?.message ?? 'network error'} — results ${INCOMPLETE} (the repo could not be fetched).`
    );
    return { source: `${owner}/${repo}`, files: [], notes };
  }
}

/** Resolve any input (URL | owner/repo | local path) to a RepoTree. */
export async function fetchTree(input: string, onProgress?: OnProgress): Promise<RepoTree> {
  if (isLocalPath(input)) return readLocalTree(input);
  const parsed = parseRepoUrl(input);
  if (!parsed) {
    return {
      source: input,
      files: [],
      notes: [`Could not parse "${input}" as a GitHub repo or local path.`],
    };
  }
  return fetchGitHubTree(parsed.owner, parsed.repo, onProgress);
}
