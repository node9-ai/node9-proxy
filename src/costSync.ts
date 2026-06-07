// src/costSync.ts
// Background cost sync: reads Claude Code session data and posts daily cost
// summaries to the Node9 backend every 10 minutes.
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getCredentials } from './config';
import { HOOK_DEBUG_LOG } from './audit';

const SYNC_INTERVAL_MS = 10 * 60 * 1000;

// Pricing now lives in src/pricing/litellm.ts — fetched from the
// LiteLLM community-maintained JSON with a bundled fallback. Stops the
// "your numbers are wrong" complaints when Anthropic / OpenAI / Google
// ship a new model.
import { ensurePricingLoaded, pricingFor, normalizeModel } from './pricing/litellm.js';

type DailyEntry = {
  date: string;
  model: string;
  /** Project working directory the session ran in. Optional for back-compat with older BE. */
  workingDir?: string;
  /** Agent session id (the JSONL filename stem). Empty for older BE / unknown. */
  runId?: string;
  costUSD: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
};

/**
 * Claude Code stores per-project sessions under
 * `~/.claude/projects/<encoded-cwd>/<session>.jsonl`, where `<encoded-cwd>`
 * is the absolute path with `/` replaced by `-` (e.g. `/home/nadav/node9` →
 * `-home-nadav-node9`). The decoding is lossy when a real path component
 * contains `-`, so we treat this as a hint only — the per-row `cwd` field
 * inside the JSONL (when present) is the authoritative source.
 */
export function decodeProjectDirName(dirName: string): string {
  return dirName.replace(/-/g, '/');
}

export function parseJSONLFile(
  filePath: string,
  fallbackWorkingDir: string
): Map<string, DailyEntry> {
  // Claude Code's JSONL filename IS the session_id (UUID). Stamp every
  // emitted DailyEntry with it so the BE can produce per-session
  // tokens + cost via `WHERE runId = X`.
  const runId = path.basename(filePath, '.jsonl');
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return new Map();
  }

  const daily = new Map<string, DailyEntry>();

  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    let row: Record<string, unknown>;
    try {
      row = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }

    if (row['type'] !== 'assistant') continue;
    const msg = row['message'] as Record<string, unknown> | undefined;
    if (!msg?.['usage'] || typeof msg['model'] !== 'string') continue;

    const usage = msg['usage'] as Record<string, unknown>;
    const model = msg['model'] as string;
    const timestamp = row['timestamp'];
    if (typeof timestamp !== 'string' || timestamp.length < 10) continue;

    const date = timestamp.slice(0, 10);
    const p = pricingFor(model);
    if (!p) continue;

    const inp = Number(usage['input_tokens'] ?? 0);
    const out = Number(usage['output_tokens'] ?? 0);
    const cw = Number(usage['cache_creation_input_tokens'] ?? 0);
    const cr = Number(usage['cache_read_input_tokens'] ?? 0);
    const cost = inp * p[0] + out * p[1] + cw * p[2] + cr * p[3];

    // Authoritative: per-row `cwd` if present; otherwise the decoded dir name.
    const rowCwd = typeof row['cwd'] === 'string' ? (row['cwd'] as string) : null;
    const workingDir = rowCwd && rowCwd.startsWith('/') ? rowCwd : fallbackWorkingDir;

    const norm = normalizeModel(model);
    // Aggregate by date::model::workingDir::runId so each session gets
    // its own row. Daily totals still recover via SUM(...) GROUP BY date
    // on the BE; per-session totals via WHERE runId = X.
    const key = `${date}::${norm}::${workingDir}::${runId}`;
    const prev = daily.get(key);
    if (prev) {
      prev.costUSD += cost;
      prev.inputTokens += inp;
      prev.outputTokens += out;
      prev.cacheWriteTokens += cw;
      prev.cacheReadTokens += cr;
    } else {
      daily.set(key, {
        date,
        model: norm,
        workingDir,
        runId,
        costUSD: cost,
        inputTokens: inp,
        outputTokens: out,
        cacheWriteTokens: cw,
        cacheReadTokens: cr,
      });
    }
  }

  return daily;
}

export type { DailyEntry };

/**
 * Walk every Claude Code session JSONL under ~/.claude/projects, parse
 * cost+tokens via parseJSONLFile, and combine into DailyEntry[] keyed
 * by (date, model, workingDir, runId). Pure (read-only fs walk); no
 * network. Used by the periodic cost-sync POST and by the Ink
 * dashboard's HIGH LEVEL strip.
 *
 * Cost: O(total JSONL bytes). On a heavy 90-day install this can take
 * 1-5s. Callers should run async + cache the result.
 */
/**
 * Collect cost entries from ~/.claude/projects.
 *
 * @param sinceMs Optional epoch-ms cutoff. Files whose mtime is older are
 *   skipped entirely (cheap fs.statSync; saves the JSON.parse over hundreds
 *   of thousands of lines from years-old sessions). The dashboard passes
 *   `Date.now() - 60 days` so HIGH LEVEL's "since open" delta still has the
 *   recent-history baseline it needs without re-parsing the user's entire
 *   life on every mount. The cost-sync uploader path leaves it undefined to
 *   preserve "all history" semantics.
 */
// ── Cost sources (GAP-3) ────────────────────────────────────────────────────
// A CostSource yields normalized DailyEntry[] for one agent. Each source owns
// its own I/O (Claude walks a dir of JSONL; a future Codex source queries
// SQLite — see gap3-codex-cost-adapter.md), so the abstraction can't assume a
// "dir of .jsonl" shape. collectEntries() merges across all available sources.
export interface CostSource {
  id: string;
  /** True when this agent's data is present on disk (and any deps are usable). */
  available(): boolean;
  /** Normalized cost rows. `sinceMs` is an optional epoch-ms mtime cutoff. */
  collect(sinceMs?: number): DailyEntry[];
}

/** Stable per-entry key — must match parseJSONLFile's aggregation key. */
function entryKey(e: DailyEntry): string {
  return `${e.date}::${e.model}::${e.workingDir ?? ''}::${e.runId ?? ''}`;
}

// Claude Code source: walk ~/.claude/projects/<enc-cwd>/<session>.jsonl.
// This is the original collectEntries body, unchanged — behaviour-preserving.
export const claudeSource: CostSource = {
  id: 'claude',
  available(): boolean {
    return fs.existsSync(path.join(os.homedir(), '.claude', 'projects'));
  },
  collect(sinceMs?: number): DailyEntry[] {
    const projectsDir = path.join(os.homedir(), '.claude', 'projects');
    if (!fs.existsSync(projectsDir)) return [];

    const combined = new Map<string, DailyEntry>();

    let dirs: string[];
    try {
      dirs = fs.readdirSync(projectsDir);
    } catch {
      return [];
    }

    for (const dir of dirs) {
      const dirPath = path.join(projectsDir, dir);
      try {
        if (!fs.statSync(dirPath).isDirectory()) continue;
      } catch {
        continue;
      }

      let files: string[];
      try {
        files = fs.readdirSync(dirPath).filter((f) => f.endsWith('.jsonl'));
      } catch {
        continue;
      }

      const fallbackWorkingDir = decodeProjectDirName(dir);
      for (const file of files) {
        const filePath = path.join(dirPath, file);
        // mtime cutoff — skip files that are entirely older than the window.
        // Saves the read+JSON.parse cost on years-old session files. Even on
        // the SaaS-sync (full-history) path the cost is one stat per file,
        // negligible compared to the parse it skips.
        if (sinceMs !== undefined) {
          try {
            if (fs.statSync(filePath).mtimeMs < sinceMs) continue;
          } catch {
            continue;
          }
        }
        const entries = parseJSONLFile(filePath, fallbackWorkingDir);
        for (const [key, e] of entries) {
          const prev = combined.get(key);
          if (prev) {
            prev.costUSD += e.costUSD;
            prev.inputTokens += e.inputTokens;
            prev.outputTokens += e.outputTokens;
            prev.cacheWriteTokens += e.cacheWriteTokens;
            prev.cacheReadTokens += e.cacheReadTokens;
          } else {
            combined.set(key, { ...e });
          }
        }
      }
    }

    return [...combined.values()];
  },
};

// Registry. Codex source is added in GAP-3 Phase 2.
const COST_SOURCES: CostSource[] = [claudeSource];

/**
 * Collect cost entries across all available agents. Merges by
 * (date, model, workingDir, runId) so a future source can't accidentally
 * collide with another. For Claude-only this is byte-identical to the previous
 * single-source implementation. A throwing source is skipped, never fatal.
 */
export function collectEntries(sinceMs?: number): DailyEntry[] {
  const combined = new Map<string, DailyEntry>();
  for (const src of COST_SOURCES) {
    let rows: DailyEntry[];
    try {
      if (!src.available()) continue;
      rows = src.collect(sinceMs);
    } catch {
      continue; // one bad source must not sink the whole sync
    }
    for (const e of rows) {
      const key = entryKey(e);
      const prev = combined.get(key);
      if (prev) {
        prev.costUSD += e.costUSD;
        prev.inputTokens += e.inputTokens;
        prev.outputTokens += e.outputTokens;
        prev.cacheWriteTokens += e.cacheWriteTokens;
        prev.cacheReadTokens += e.cacheReadTokens;
      } else {
        combined.set(key, { ...e });
      }
    }
  }
  return [...combined.values()];
}

async function syncCost(): Promise<void> {
  const creds = getCredentials();
  if (!creds?.apiKey || !creds?.apiUrl) return;

  // Make sure LiteLLM pricing is loaded before parsing entries —
  // pricingFor() falls back to bundled defaults if this fails, so
  // we never block cost-sync on a network hiccup.
  await ensurePricingLoaded();

  const entries = collectEntries();
  if (entries.length === 0) return;

  let username = 'unknown';
  try {
    username = os.userInfo().username;
  } catch {}
  const machineId = `${os.hostname()}:${username}`;

  try {
    const res = await fetch(`${creds.apiUrl}/cost-sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${creds.apiKey}` },
      body: JSON.stringify({ machineId, entries }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      fs.appendFileSync(HOOK_DEBUG_LOG, `[cost-sync] HTTP ${res.status}\n`);
    }
  } catch (err) {
    fs.appendFileSync(HOOK_DEBUG_LOG, `[cost-sync] ${(err as Error).message}\n`);
  }
}

export function startCostSync(): void {
  syncCost().catch(() => {});
  const timer = setInterval(() => {
    syncCost().catch(() => {});
  }, SYNC_INTERVAL_MS);
  timer.unref();
}
