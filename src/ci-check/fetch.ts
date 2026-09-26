// src/ci-check/fetch.ts
// Fetch the agent-surface files of a repo — either a GitHub URL (via the
// Contents API, no clone) or a local path. CONFIG ONLY: we fetch a fixed set of
// config files, never source, and never execute anything. Every network failure
// degrades to a note (fail-open) so a rate-limit or missing dir never throws.

import fs from 'fs';
import path from 'path';
import posixPath from 'path/posix';
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

type Kind = 'file' | 'link' | 'other';

/** Kind from a git mode (`git ls-files -s`, `git ls-tree`, the Trees API). */
function kindOfMode(mode: string): Kind {
  if (mode === '120000') return 'link';
  if (mode === '100644' || mode === '100755') return 'file';
  return 'other'; // 160000 submodule, 040000 tree
}

const INCOMPLETE = 'may be INCOMPLETE';

/** One text form for every reader: a checkout written with `eol=crlf` has CRLF where the blob
 *  has LF (hermes-agent's install.ps1), and every check reads line by line. Without this, the
 *  local and git readers disagree on content that is the same file. */
const lf = (t: string): string => t.replace(/\r\n/g, '\n');
const tooLargeNote = (rel: string) =>
  `${rel} is larger than ${MAX_FILE_BYTES / (1024 * 1024)} MiB — not read; results ${INCOMPLETE}.`;
const outsideNote = (rel: string) =>
  `${rel} is a symlink that points outside the repository — not read.`;

/** The ONE plan: which paths are read, in order. The fixed root surface files and the root
 *  workflows always come first and are never capped; nested surface files follow, through the
 *  one selector, capped only where the reader pays per file (the API). */
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

type LinkOutcome = { target: string } | { skip: 'dangling' | 'outside' | 'directory' };

/** The ONE symlink rule. A link whose text resolves (relative to its own directory, up to
 *  MAX_LINK_HOPS) to a regular file inside the repository is read as that file's content under
 *  the link's own path — the agent loads exactly that. A link that leaves the repository is not
 *  read (and noted); dangling and directory links are not read. Decided from the listing and
 *  the link text only, never from the host filesystem, so every reader agrees. */
function resolveLink(
  linkPath: string,
  kindOf: (p: string) => Kind | undefined,
  textOf: (p: string) => string | null,
  isDir: (p: string) => boolean
): LinkOutcome {
  let cur = linkPath;
  for (let hop = 0; hop < MAX_LINK_HOPS; hop++) {
    const text = textOf(cur);
    if (text === null) return { skip: 'dangling' };
    const t = text.trim();
    if (t.startsWith('/') || /^[A-Za-z]:[\\/]/.test(t) || t.startsWith('\\\\'))
      return { skip: 'outside' };
    const next = posixPath.normalize(posixPath.join(posixPath.dirname(cur), t.replace(/\\/g, '/')));
    if (next === '..' || next.startsWith('../')) return { skip: 'outside' };
    const k = kindOf(next);
    if (k === 'file') return { target: next };
    if (k === 'link') {
      cur = next;
      continue;
    }
    return isDir(next) ? { skip: 'directory' } : { skip: 'dangling' };
  }
  return { skip: 'dangling' }; // the OS gives up too (ELOOP): nothing for the agent to load
}

function dirTester(paths: string[]): (p: string) => boolean {
  const dirs = new Set<string>();
  for (const p of paths)
    for (let i = p.indexOf('/'); i > 0; i = p.indexOf('/', i + 1)) dirs.add(p.slice(0, i));
  return (p) => dirs.has(p);
}

// ── local working tree ───────────────────────────────────────────────────────

const OPEN_NOFOLLOW = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);

/** What is on disk at `rel`, without following a link: a regular file (with its size), a
 *  link, or nothing readable. One open, one fstat on that handle — no check-then-read race. */
function probe(
  root: string,
  rel: string
): { kind: 'file'; size: number } | { kind: 'link' | 'none' } {
  let fd: number | undefined;
  try {
    fd = fs.openSync(path.join(root, rel), OPEN_NOFOLLOW);
    const st = fs.fstatSync(fd);
    return st.isFile() ? { kind: 'file', size: st.size } : { kind: 'none' };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    return code === 'ELOOP' || code === 'EMLINK' ? { kind: 'link' } : { kind: 'none' };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Read a regular file through one O_NOFOLLOW handle, refusing anything over the limit. */
function readCapped(abs: string): string | null {
  let fd: number | undefined;
  try {
    fd = fs.openSync(abs, OPEN_NOFOLLOW);
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    return lf(fs.readFileSync(fd, 'utf8'));
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** A link's text on disk. With `core.symlinks=false` (Windows) git checks a link out as a small
 *  text file holding the link text; the index still says 120000, so read it as text. */
function localLinkText(root: string, rel: string, indexSaysLink: boolean): string | null {
  const abs = path.join(root, rel);
  try {
    return fs.readlinkSync(abs);
  } catch {
    if (!indexSaysLink) return null;
    const t = readCapped(abs);
    return t !== null && t.length <= 4096 ? t : null;
  }
}

/** The working tree's listing from git: tracked files with their modes, plus untracked files
 *  that are not ignored (a developer's CLI run should see a file they have not committed yet).
 *  null when `root` is not inside a git work tree or git is unavailable. */
function gitWorkTreeListing(root: string): { path: string; kind: Kind | 'unknown' }[] | null {
  const run = (args: string[]): string | null => {
    try {
      return execFileSync('git', ['-C', root, ...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        maxBuffer: 256 * 1024 * 1024,
        timeout: 60_000,
      });
    } catch {
      return null;
    }
  };
  const tracked = run(['ls-files', '-z', '-s', '--cached']);
  if (tracked === null) return null;
  const out: { path: string; kind: Kind | 'unknown' }[] = [];
  const seen = new Set<string>();
  for (const line of tracked.split('\0')) {
    const tab = line.indexOf('\t');
    if (tab < 0) continue;
    const p = line.slice(tab + 1);
    if (seen.has(p)) continue; // unmerged entries repeat a path with stages 1–3
    seen.add(p);
    out.push({ path: p, kind: kindOfMode(line.slice(0, line.indexOf(' '))) });
  }
  for (const p of (run(['ls-files', '-z', '--others', '--exclude-standard']) ?? '').split('\0')) {
    if (p && !seen.has(p)) {
      seen.add(p);
      out.push({ path: p, kind: 'unknown' });
    }
  }
  return out;
}

/** A folder that is not a git work tree (a CLI run on a plain directory): walk it, bounded.
 *  Never the PR gate — the Action always scans a checkout. */
function walkListing(
  root: string,
  notes: string[]
): { entries: { path: string; kind: Kind }[]; complete: boolean } {
  const entries: { path: string; kind: Kind }[] = [];
  const MAX_DIRS = 5000; // dir-visit budget so a huge tree can't turn a scan into a full crawl
  let dirsVisited = 0;
  const walk = (relDir: string) => {
    if (dirsVisited >= MAX_DIRS) return;
    dirsVisited++;
    let dirents: fs.Dirent[];
    try {
      dirents = fs.readdirSync(path.join(root, relDir), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of dirents) {
      if (dirsVisited >= MAX_DIRS) return;
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (IGNORE_HARD.test(`${rel}/`)) continue; // never descend into node_modules & co.
        walk(rel);
      } else if (e.isSymbolicLink()) entries.push({ path: rel, kind: 'link' });
      else if (e.isFile()) entries.push({ path: rel, kind: 'file' });
    }
  };
  walk('');
  const complete = dirsVisited < MAX_DIRS;
  if (!complete)
    notes.push(
      `repo is large — some agent-surface files ${INCOMPLETE} (stopped after ${MAX_DIRS} directories).`
    );
  return { entries, complete };
}

/** Read the agent surface of a local directory. Lists through git when it is a git work tree
 *  (the Action's checkout, a developer's clone) so the listing is the same one the PR base
 *  reader sees; walks the folder otherwise. Content is NOT read here: each file is read when
 *  scanTree asks for it and then let go, so memory is bounded by one file, not by the repo. */
export function readLocalTree(dir: string): RepoTree {
  const root = dir.replace(/^~/, process.env.HOME ?? '~');
  const notes: string[] = [];
  const fromGit = gitWorkTreeListing(root);
  const walked = fromGit ? null : walkListing(root, notes);
  const kinds = new Map<string, Kind | 'unknown'>(
    fromGit
      ? fromGit.map((e) => [e.path, e.kind] as const)
      : walked!.entries.map((e) => [e.path, e.kind] as const)
  );
  const paths = [...kinds.keys()];
  const indexLinks = new Set(paths.filter((p) => kinds.get(p) === 'link'));
  const kindOf = (p: string): Kind | undefined => {
    const k = kinds.get(p);
    if (k === undefined) return undefined;
    if (k !== 'unknown') return k;
    const pr = probe(root, p);
    const resolved: Kind = pr.kind === 'file' ? 'file' : pr.kind === 'link' ? 'link' : 'other';
    kinds.set(p, resolved);
    return resolved;
  };
  const isDir = dirTester(paths);
  const files: RepoFile[] = [];
  const planLocal = planSurface(paths, notes);
  const plannedLocal = new Set(planLocal);
  for (const rel of planLocal) {
    let target = rel;
    if (kindOf(rel) === 'link') {
      const r = resolveLink(rel, kindOf, (p) => localLinkText(root, p, indexLinks.has(p)), isDir);
      if ('skip' in r) {
        if (r.skip === 'outside') notes.push(outsideNote(rel));
        continue;
      }
      // Already read under its own name (AGENTS.md -> CLAUDE.md): grading it twice only
      // duplicates every finding. A link to a file NOT otherwise read is read here.
      if (plannedLocal.has(r.target)) continue;
      target = r.target;
    } else if (kindOf(rel) !== 'file') continue;
    const pr = probe(root, target);
    if (pr.kind !== 'file') continue; // listed but gone, or not what git says it is
    if (pr.size > MAX_FILE_BYTES) {
      notes.push(tooLargeNote(rel));
      continue;
    }
    const abs = path.join(root, target);
    files.push({
      path: rel,
      // Read on demand, not held: scanTree reads each file once, analyzes it, and moves on.
      get content(): string {
        return readCapped(abs) ?? '';
      },
    });
  }
  return { source: root, files, notes, paths, pathsComplete: fromGit ? true : walked!.complete };
}

// ── a git ref (the PR base) ──────────────────────────────────────────────────

/** Many blobs through ONE `git cat-file --batch` process (a process per file took 9.7 s on
 *  a 1,577-file base; one batch takes 0.12 s). Returns sha → text; missing objects are absent.
 *  Throws when the batch cannot be run — the caller turns that into "the base did not run". */
function catFileBatch(root: string, shas: string[]): Map<string, string> {
  const out = new Map<string, string>();
  if (shas.length === 0) return out;
  const buf = execFileSync('git', ['-C', root, 'cat-file', '--batch'], {
    input: shas.join('\n') + '\n',
    stdio: ['pipe', 'pipe', 'ignore'],
    maxBuffer: 512 * 1024 * 1024,
    timeout: 120_000,
  });
  let i = 0;
  while (i < buf.length) {
    const nl = buf.indexOf(0x0a, i);
    if (nl < 0) break;
    const header = buf.toString('utf8', i, nl).split(' ');
    i = nl + 1;
    if (header[1] === 'missing' || header.length < 3) continue;
    const size = Number(header[2]);
    out.set(header[0], lf(buf.toString('utf8', i, i + size)));
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
      return execFileSync('git', ['-C', root, ...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
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
    const [mode, , objSha, size] = line.slice(0, tab).split(/\s+/);
    entries.set(line.slice(tab + 1), {
      kind: kindOfMode(mode),
      sha: objSha,
      size: Number(size) || 0,
    });
  }
  const paths = [...entries.keys()];
  const notes: string[] = [];
  try {
    // Every link's text in one batch (links are small), so resolution needs no more processes.
    const linkShas = [...entries.values()].filter((e) => e.kind === 'link').map((e) => e.sha);
    const linkText = catFileBatch(root, [...new Set(linkShas)]);
    const kindOf = (p: string) => entries.get(p)?.kind;
    const textOf = (p: string) => {
      const e = entries.get(p);
      return e && e.kind === 'link' ? (linkText.get(e.sha) ?? null) : null;
    };
    const isDir = dirTester(paths);
    const planned: { rel: string; sha: string }[] = [];
    const planGit = planSurface(paths, notes);
    const plannedGit = new Set(planGit);
    for (const rel of planGit) {
      let target = rel;
      if (kindOf(rel) === 'link') {
        const r = resolveLink(rel, kindOf, textOf, isDir);
        if ('skip' in r) {
          if (r.skip === 'outside') notes.push(outsideNote(rel));
          continue;
        }
        if (plannedGit.has(r.target)) continue; // read under its own name (see readLocalTree)
        target = r.target;
      } else if (kindOf(rel) !== 'file') continue;
      const e = entries.get(target)!;
      if (e.size > MAX_FILE_BYTES) {
        notes.push(tooLargeNote(rel));
        continue;
      }
      planned.push({ rel, sha: e.sha });
    }
    const bytes = catFileBatch(root, [...new Set(planned.map((x) => x.sha))]);
    const files: RepoFile[] = [];
    for (const { rel, sha: s } of planned) {
      const content = bytes.get(s);
      if (content !== undefined) files.push({ path: rel, content });
    }
    return { source: `${root}@${ref}`, files, notes, paths, pathsComplete: true };
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

/** One blob by sha — the Git Blobs API, not Contents: Contents returns a file over 1 MB with an
 *  EMPTY body (hermes-agent's 1,077,327-byte llms-full.md read as nothing) and a symlink with
 *  no content at all. Blobs returns both. */
async function fetchBlob(
  owner: string,
  repo: string,
  sha: string,
  notes: string[]
): Promise<string | null> {
  const { status, json } = await ghGet(
    `https://api.github.com/repos/${owner}/${repo}/git/blobs/${sha}`
  );
  if (status === 403 || status === 429) {
    if (!notes.includes(RATE_LIMIT_NOTE)) notes.push(RATE_LIMIT_NOTE);
    return null;
  }
  if (status === 0) {
    if (!notes.includes(NETWORK_NOTE)) notes.push(NETWORK_NOTE);
    return null;
  }
  if (status !== 200 || !json || typeof json !== 'object') return null;
  const b = json as { content?: unknown; encoding?: unknown };
  if (typeof b.content !== 'string') return null;
  return lf(
    b.encoding === 'base64' ? Buffer.from(b.content, 'base64').toString('utf8') : b.content
  );
}

const FETCH_CONCURRENCY = 8;

/** Fetch the agent-surface of a GitHub repo. Never throws — network/absence failures become
 *  notes; the checks run over whatever we got. The same plan, symlink rule and per-file limit
 *  as the local and git readers; capped at API_CAPS nested files because each costs a request. */
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
    const entries = new Map(listed.entries.map((e) => [e.path, e]));
    const paths = [...entries.keys()];
    const kindOf = (p: string): Kind | undefined => {
      const e = entries.get(p);
      return e ? (e.type === 'blob' ? kindOfMode(e.mode) : 'other') : undefined;
    };
    const planned = planSurface(paths, notes, {
      nestedCap: API_CAPS.files,
      truncated: listed.truncated,
    });

    // Link texts are small blobs, fetched as a chain is walked; then the one symlink rule.
    const linkText = new Map<string, string | null>();
    const textOf = (p: string) => linkText.get(p) ?? null;
    const isDir = dirTester(paths);
    const reads: { rel: string; sha: string }[] = [];
    const plannedApi = new Set(planned);
    for (const rel of planned) {
      let target = rel;
      if (kindOf(rel) === 'link') {
        let cur = rel;
        for (let hop = 0; hop < MAX_LINK_HOPS && kindOf(cur) === 'link'; hop++) {
          if (!linkText.has(cur))
            linkText.set(cur, await fetchBlob(owner, repo, entries.get(cur)!.sha, notes));
          const t = linkText.get(cur);
          if (t === null || t === undefined) break;
          const next = posixPath.normalize(posixPath.join(posixPath.dirname(cur), t.trim()));
          if (kindOf(next) !== 'link') break;
          cur = next;
        }
        const r = resolveLink(rel, kindOf, textOf, isDir);
        if ('skip' in r) {
          if (r.skip === 'outside') notes.push(outsideNote(rel));
          continue;
        }
        if (plannedApi.has(r.target)) continue; // read under its own name (see readLocalTree)
        target = r.target;
      } else if (kindOf(rel) !== 'file') continue;
      const e = entries.get(target)!;
      if ((e.size ?? 0) > MAX_FILE_BYTES) {
        notes.push(tooLargeNote(rel));
        continue;
      }
      reads.push({ rel, sha: e.sha });
    }

    let done = 0;
    const fetched = await pooled(reads, FETCH_CONCURRENCY, async ({ rel, sha }) => {
      const content = await fetchBlob(owner, repo, sha, notes);
      onProgress?.({ phase: 'fetching agent surface', done: ++done, total: reads.length });
      return content === null ? null : { path: rel, content };
    });
    return {
      source: `${owner}/${repo}`,
      files: fetched.filter((f): f is RepoFile => !!f),
      notes,
      paths,
      pathsComplete: !listed.truncated,
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
