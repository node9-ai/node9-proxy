// src/costSync.ts
// Background cost sync: reads Claude Code session data and posts daily cost
// summaries to the Node9 backend every 10 minutes.
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getCredentials } from './config';
import { HOOK_DEBUG_LOG } from './audit';

const SYNC_INTERVAL_MS = 10 * 60 * 1000;

// USD per token for known model families (input / output / cache-write / cache-read)
const PRICING: Record<string, readonly [number, number, number, number]> = {
  'claude-opus-4': [5e-6, 25e-6, 6.25e-6, 0.5e-6],
  'claude-sonnet-4': [3e-6, 15e-6, 3.75e-6, 0.3e-6],
  'claude-haiku-4': [0.8e-6, 4e-6, 1e-6, 0.08e-6],
  'claude-3-7-sonnet': [3e-6, 15e-6, 3.75e-6, 0.3e-6],
  'claude-3-5-sonnet': [3e-6, 15e-6, 3.75e-6, 0.3e-6],
  'claude-3-5-haiku': [0.8e-6, 4e-6, 1e-6, 0.08e-6],
  'claude-3-haiku': [0.25e-6, 1.25e-6, 0.3e-6, 0.03e-6],
};

// Strip the date suffix Anthropic appends to model IDs (e.g. -20251101)
function normalizeModel(raw: string): string {
  return raw.replace(/-\d{8}$/, '');
}

function pricingFor(model: string): readonly [number, number, number, number] | null {
  const norm = normalizeModel(model);
  if (PRICING[norm]) return PRICING[norm]!;
  // Longest-prefix match for future model names
  let best: string | null = null;
  for (const key of Object.keys(PRICING)) {
    if (norm.startsWith(key) && (best === null || key.length > best.length)) best = key;
  }
  return best ? PRICING[best]! : null;
}

type DailyEntry = {
  date: string;
  model: string;
  costUSD: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
};

function parseJSONLFile(filePath: string): Map<string, DailyEntry> {
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

    const norm = normalizeModel(model);
    const key = `${date}::${norm}`;
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

    for (const file of files) {
      const entries = parseJSONLFile(path.join(dirPath, file));
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
