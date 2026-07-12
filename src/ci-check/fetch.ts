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
const SURFACE_FILES = [
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
const SURFACE_BASENAME =
  /(^|\/)(CLAUDE|AGENTS|GEMINI)\.md$|(^|\/)\.cursorrules$|(^|\/)\.(windsurf|cline)rules$|(^|\/)copilot-instructions\.md$|(^|\/)\.claude\/settings(\.local)?\.json$|(^|\/)\.mcp\.json$|(^|\/)\.cursor\/mcp\.json$|(^|\/)\.codex\/config\.toml$/;
// Paths under these segments are dependencies / build output, not the repo's OWN agent
// surface — skip them (a vendored `node_modules/**/CLAUDE.md` is noise, not the repo's risk).
const IGNORE_SEG =
  /(^|\/)(node_modules|vendor|\.git|dist|build|out|\.next|target|\.venv|site-packages)\//;
const MAX_SURFACE_FILES = 200;

/** Pure: from a flat list of repo file paths, pick the agent-surface files at any depth,
 *  skipping dependency/build dirs, capped at MAX_SURFACE_FILES. Pushes a note (marked
 *  INCOMPLETE so `scanTree` flips `incomplete`) if the tree was truncated or the cap was hit —
 *  a large monorepo must never be silently under-scanned. Shared by the GitHub Trees path and
 *  local recursion. */
export function pickSurfacePaths(paths: string[], truncated: boolean, notes: string[]): string[] {
  const matched = paths.filter((p) => SURFACE_BASENAME.test(p) && !IGNORE_SEG.test(p));
  const capped = matched.slice(0, MAX_SURFACE_FILES);
  if (truncated || matched.length > MAX_SURFACE_FILES) {
    notes.push(
      `repo tree is large/truncated — some agent-surface files may be INCOMPLETE (scanned ${capped.length} of ${matched.length}${truncated ? '+' : ''}).`
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

/** 1c-B: discover agent-surface files at ANY depth via the Git Trees API (one recursive
 *  call — `HEAD` resolves directly, verified). Returns the picked paths, or `null` on a
 *  fetch failure so the caller can FALL BACK to the fixed root list (never worse than the
 *  old root-only behavior). Never throws. */
async function listSurfacePaths(
  owner: string,
  repo: string,
  notes: string[]
): Promise<string[] | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`;
  const { status, json } = await ghGet(url);
  if (status === 403 || status === 429) {
    if (!notes.includes(RATE_LIMIT_NOTE)) notes.push(RATE_LIMIT_NOTE);
    return null; // couldn't discover → fall back to the root list
  }
  if (status === 0) {
    if (!notes.includes(NETWORK_NOTE)) notes.push(NETWORK_NOTE);
    return null;
  }
  if (status !== 200 || !json || typeof json !== 'object') return null;
  const tree = json as { tree?: { path?: string; type?: string }[]; truncated?: boolean };
  if (!Array.isArray(tree.tree)) return null;
  const paths = tree.tree
    .filter((e) => e.type === 'blob' && typeof e.path === 'string')
    .map((e) => e.path as string);
  return pickSurfacePaths(paths, !!tree.truncated, notes);
}

const FETCH_CONCURRENCY = 8;

/** Fetch the agent-surface of a GitHub repo. Never throws — network/absence
 *  failures become notes; the checks run over whatever we got. Fetches run
 *  concurrently (bounded) so a many-workflow repo doesn't serialize. */
export async function fetchGitHubTree(
  owner: string,
  repo: string,
  onProgress?: OnProgress
): Promise<RepoTree> {
  const notes: string[] = [];
  try {
    onProgress?.({ phase: 'listing workflows', done: 0, total: 1 });
    const workflowPaths = await listWorkflowPaths(owner, repo, notes);
    // 1c-B: discover the surface at ANY depth, then ALWAYS union the fixed ROOT list. On the
    // success path `discovered` is a superset of the root files (the union just dedups); on a
    // TRUNCATED tree / cap / Trees failure the union guarantees the root files are still
    // fetched — so a deep scan can never look at LESS than the old root-only baseline.
    const discovered = await listSurfacePaths(owner, repo, notes);
    const allPaths = [...new Set([...SURFACE_FILES, ...(discovered ?? []), ...workflowPaths])];
    let done = 0;
    const fetched = await pooled(allPaths, FETCH_CONCURRENCY, async (p) => {
      const f = await fetchOne(owner, repo, p, notes);
      onProgress?.({ phase: 'fetching agent surface', done: ++done, total: allPaths.length });
      return f;
    });
    return { source: `${owner}/${repo}`, files: fetched.filter((f): f is RepoFile => !!f), notes };
  } catch (err) {
    // "may be INCOMPLETE" is load-bearing — index.ts keys `incomplete` off it, so a total
    // fetch failure is never rendered as a clean bill of health.
    notes.push(
      `fetch degraded: ${(err as Error)?.message ?? 'network error'} — results may be INCOMPLETE (the repo could not be fetched).`
    );
    return { source: `${owner}/${repo}`, files: [], notes };
  }
}

/** Read the agent-surface from a local directory (no network). */
export function readLocalTree(dir: string): RepoTree {
  const root = dir.replace(/^~/, process.env.HOME ?? '~');
  const files: RepoFile[] = [];
  const notes: string[] = [];
  const add = (rel: string) => {
    const abs = path.join(root, rel);
    try {
      if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
        files.push({ path: rel, content: fs.readFileSync(abs, 'utf8') });
      }
    } catch {
      /* unreadable → skip */
    }
  };
  const seen = new Set<string>();
  const collect = (rel: string) => {
    if (seen.has(rel)) return;
    seen.add(rel);
    add(rel);
  };
  // Always include the fixed ROOT surface files first (never scan LESS than the old
  // baseline), THEN recurse for NESTED ones (1c-B). The caps bound only the recursive walk.
  for (const p of SURFACE_FILES) collect(p);
  // Recurse for agent-surface files at any depth (bounded, skip dep/build dirs), the local
  // twin of the Trees-API discovery. POSIX-separator rel paths so SURFACE_BASENAME /
  // IGNORE_SEG match identically to the GitHub side. Symlinked dirs are skipped (Dirent
  // .isDirectory() is false for a symlink) so there is no symlink-loop risk.
  const matches: string[] = [];
  const MAX_DIRS = 5000; // dir-visit budget so a huge tree can't turn a scan into a full crawl
  let dirsVisited = 0;
  const walk = (relDir: string) => {
    if (matches.length >= MAX_SURFACE_FILES || dirsVisited >= MAX_DIRS) return;
    dirsVisited++;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(path.join(root, relDir), { withFileTypes: true });
    } catch {
      return; // unreadable dir → skip
    }
    for (const e of entries) {
      if (matches.length >= MAX_SURFACE_FILES || dirsVisited >= MAX_DIRS) return;
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (IGNORE_SEG.test(`${rel}/`)) continue;
        walk(rel);
      } else if (e.isFile() && SURFACE_BASENAME.test(rel)) {
        matches.push(rel);
      }
    }
  };
  walk('');
  if (matches.length >= MAX_SURFACE_FILES || dirsVisited >= MAX_DIRS)
    notes.push(
      `repo is large — some agent-surface files may be INCOMPLETE (capped at ${MAX_SURFACE_FILES} files / ${MAX_DIRS} dirs).`
    );
  for (const rel of matches) collect(rel);
  const wfDir = path.join(root, WORKFLOW_DIR);
  try {
    if (fs.existsSync(wfDir)) {
      for (const name of fs.readdirSync(wfDir)) {
        if (/\.ya?ml$/.test(name)) add(path.join(WORKFLOW_DIR, name));
      }
    }
  } catch {
    /* unreadable workflows dir → skip */
  }
  return { source: root, files, notes };
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
