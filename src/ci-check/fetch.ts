// src/ci-check/fetch.ts
// Fetch the agent-surface files of a repo — either a GitHub URL (via the
// Contents API, no clone) or a local path. CONFIG ONLY: we fetch a fixed set of
// config files, never source, and never execute anything. Every network failure
// degrades to a note (fail-open) so a rate-limit or missing dir never throws.

import fs from 'fs';
import path from 'path';
import { request } from 'undici';
import type { RepoTree, RepoFile } from './types';

/** The committed files that make up the agent-security surface. Fixed list —
 *  we never fetch arbitrary repo content. Workflows are enumerated separately. */
const SURFACE_FILES = [
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.mcp.json',
  '.cursor/mcp.json',
  '.codex/config.toml',
];

const WORKFLOW_DIR = '.github/workflows';

export interface ParsedRepo {
  owner: string;
  repo: string;
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
  // Optional token lifts the 60/hr unauthenticated limit to 5000/hr.
  const tok = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
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
  const res = await request(url, { headers: ghHeaders() });
  const body = await res.body.text();
  let json: unknown = null;
  try {
    json = JSON.parse(body);
  } catch {
    /* non-JSON (e.g. rate-limit HTML) → leave null */
  }
  return { status: res.statusCode, json };
}

const RATE_LIMIT_NOTE =
  'GitHub rate limit hit — results may be INCOMPLETE (a missing file could be unread, not absent). Set GITHUB_TOKEN.';

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
  if (status !== 200 || !json || typeof json !== 'object') return null;
  const f = json as ContentsFile;
  if (f.type !== 'file' || typeof f.content !== 'string') return null;
  const content = Buffer.from(f.content, (f.encoding as BufferEncoding) || 'base64').toString(
    'utf8'
  );
  return { path: filePath, content };
}

async function fetchWorkflows(owner: string, repo: string, notes: string[]): Promise<RepoFile[]> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${WORKFLOW_DIR}`;
  const { status, json } = await ghGet(url);
  if (status === 403) {
    notes.push(
      'GitHub rate limit hit while listing workflows — set GITHUB_TOKEN for full coverage.'
    );
    return [];
  }
  if (status !== 200 || !Array.isArray(json)) return [];
  const entries = json as ContentsFile[];
  const ymls = entries.filter((e) => e.type === 'file' && /\.ya?ml$/.test(e.name));
  const out: RepoFile[] = [];
  for (const e of ymls) {
    const f = await fetchOne(owner, repo, e.path, notes);
    if (f) out.push(f);
  }
  return out;
}

/** Fetch the agent-surface of a GitHub repo. Never throws — network/absence
 *  failures become notes; the checks run over whatever we got. */
export async function fetchGitHubTree(owner: string, repo: string): Promise<RepoTree> {
  const files: RepoFile[] = [];
  const notes: string[] = [];
  try {
    for (const p of SURFACE_FILES) {
      const f = await fetchOne(owner, repo, p, notes);
      if (f) files.push(f);
    }
    files.push(...(await fetchWorkflows(owner, repo, notes)));
  } catch (err) {
    notes.push(`fetch degraded: ${(err as Error)?.message ?? 'network error'}`);
  }
  return { source: `${owner}/${repo}`, files, notes };
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
  for (const p of SURFACE_FILES) add(p);
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
export async function fetchTree(input: string): Promise<RepoTree> {
  if (isLocalPath(input)) return readLocalTree(input);
  const parsed = parseRepoUrl(input);
  if (!parsed) {
    return {
      source: input,
      files: [],
      notes: [`Could not parse "${input}" as a GitHub repo or local path.`],
    };
  }
  return fetchGitHubTree(parsed.owner, parsed.repo);
}
