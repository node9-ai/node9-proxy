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
    // Aggregate by date::model::workingDir so two projects on the same day
    // with the same model produce two entries, not one merged total.
    const key = `${date}::${norm}::${workingDir}`;
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

function collectEntries(): DailyEntry[] {
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
      const entries = parseJSONLFile(path.join(dirPath, file), fallbackWorkingDir);
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
