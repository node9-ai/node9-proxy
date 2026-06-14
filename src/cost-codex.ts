// src/cost-codex.ts
// GAP-3 / cost-multi-agent Phase 1 — Codex cost source (UPLOAD path).
//
// Repointed from the old ~/.codex/log/codex-tui.log (a path current Codex
// builds no longer write) to ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl —
// the same source the local dashboard reads. Each session file carries:
//   { type:'session_meta', payload:{ timestamp, id, cwd, model_provider } }
//   { type:'turn_context',  payload:{ model, cwd } }
//   { type:'event_msg', payload:{ type:'token_count',
//       info:{ total_token_usage:{ input_tokens, cached_input_tokens,
//       output_tokens } } } }   // CUMULATIVE — last one wins
//
// One DailyEntry per session: dated at session start, attributed to the
// session's model + cwd + id (runId). total_token_usage is cumulative, so we
// take the final value. See doc/cost-multi-agent-sources.md.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { pricingFor, normalizeModel } from './pricing/litellm.js';
import type { CostSource, DailyEntry } from './costSync.js';

export function codexSessionsDir(): string {
  return path.join(os.homedir(), '.codex', 'sessions');
}

// Codex/gpt-5 fallback rates [input, output, cacheWrite, cacheRead] per token —
// used only when the model isn't in the LiteLLM table (bundled now carries the
// gpt-5 family + o-series), so we never undercount a brand-new Codex model to $0.
const CODEX_FALLBACK: readonly [number, number, number, number] = [5e-6, 15e-6, 0, 2.5e-6];
/**
 * The SINGLE Codex per-token price source — `pricingFor` (LiteLLM) with a
 * conservative fallback for unknown models. Used by the upload path AND by the
 * local `node9 report` Codex reader (cli/aggregate/report-audit.ts), so both
 * price Codex per-model the same way instead of a flat hardcoded gpt-5 rate.
 */
export function codexPriceFor(model: string): readonly [number, number, number, number] {
  return pricingFor(model) ?? CODEX_FALLBACK;
}

/**
 * The SINGLE Codex cost arithmetic — per-session USD from cumulative token
 * totals, priced per-model via `codexPriceFor` (empty model → gpt-5). Used by
 * the upload parser AND every local reader (`node9 report`/`scan`/`sessions`),
 * so the price source AND the token math live in exactly one place.
 */
export function codexSessionCost(
  model: string,
  tokens: { input: number; cached: number; output: number }
): number {
  const nonCached = Math.max(0, tokens.input - tokens.cached);
  const [pin, pout, , pcr] = codexPriceFor(model || 'gpt-5');
  return nonCached * pin + tokens.cached * pcr + tokens.output * pout;
}

// Walk ~/.codex/sessions/<YYYY>/<MM>/<DD>/*.jsonl → absolute paths.
function listCodexSessionFiles(base: string): string[] {
  const out: string[] = [];
  for (const y of safeReaddir(base)) {
    const yp = path.join(base, y);
    if (!isDir(yp)) continue;
    for (const m of safeReaddir(yp)) {
      const mp = path.join(yp, m);
      if (!isDir(mp)) continue;
      for (const d of safeReaddir(mp)) {
        const dp = path.join(mp, d);
        if (!isDir(dp)) continue;
        for (const f of safeReaddir(dp)) {
          if (f.endsWith('.jsonl')) out.push(path.join(dp, f));
        }
      }
    }
  }
  return out;
}

function safeReaddir(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}
function isDir(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Parse the lines of one codex session file into a single DailyEntry, or null
 * when the session has no usable token usage / timestamp. Pure — exported for
 * unit tests.
 */
export function parseCodexSession(lines: string[]): DailyEntry | null {
  let sessionStart = '';
  let runId = '';
  let cwd = '';
  let model = '';
  let input = 0;
  let cached = 0;
  let output = 0;
  let sawUsage = false;

  for (const raw of lines) {
    if (!raw.trim()) continue;
    let entry: { type?: string; payload?: Record<string, unknown> };
    try {
      entry = JSON.parse(raw) as typeof entry;
    } catch {
      continue;
    }
    const p = (entry.payload ?? {}) as Record<string, unknown>;

    if (entry.type === 'session_meta') {
      if (!sessionStart && typeof p['timestamp'] === 'string') sessionStart = p['timestamp'];
      if (!runId && typeof p['id'] === 'string') runId = p['id'];
      if (!cwd && typeof p['cwd'] === 'string') cwd = p['cwd'];
      continue;
    }
    if (entry.type === 'turn_context') {
      if (typeof p['model'] === 'string') model = p['model']; // last wins
      if (!cwd && typeof p['cwd'] === 'string') cwd = p['cwd'];
      continue;
    }
    if (entry.type === 'event_msg' && p['type'] === 'token_count') {
      const info = (p['info'] ?? {}) as Record<string, unknown>;
      const usage = (info['total_token_usage'] ?? {}) as Record<string, number>;
      // Cumulative totals — keep the latest defined values.
      if (typeof usage['input_tokens'] === 'number') input = usage['input_tokens'];
      if (typeof usage['cached_input_tokens'] === 'number') cached = usage['cached_input_tokens'];
      if (typeof usage['output_tokens'] === 'number') output = usage['output_tokens'];
      sawUsage = true;
    }
  }

  if (!sessionStart || !sawUsage) return null;
  const nonCached = Math.max(0, input - cached);
  if (nonCached === 0 && output === 0 && cached === 0) return null;

  const norm = normalizeModel(model || 'gpt-5');
  const costUSD = codexSessionCost(model, { input, cached, output });

  return {
    date: sessionStart.slice(0, 10),
    model: norm,
    workingDir: cwd,
    runId,
    costUSD,
    inputTokens: nonCached,
    outputTokens: output,
    cacheReadTokens: cached,
    cacheWriteTokens: 0,
  };
}

export const codexSource: CostSource = {
  id: 'codex',
  available(): boolean {
    try {
      return fs.existsSync(codexSessionsDir());
    } catch {
      return false;
    }
  },
  collect(sinceMs?: number): DailyEntry[] {
    const base = codexSessionsDir();
    const combined = new Map<string, DailyEntry>();
    for (const file of listCodexSessionFiles(base)) {
      try {
        if (sinceMs !== undefined && fs.statSync(file).mtimeMs < sinceMs) continue;
      } catch {
        continue;
      }
      let content: string;
      try {
        content = fs.readFileSync(file, 'utf8');
      } catch {
        continue;
      }
      const e = parseCodexSession(content.split('\n'));
      if (!e) continue;
      const key = `${e.date}::${e.model}::${e.workingDir ?? ''}::${e.runId ?? ''}`;
      const prev = combined.get(key);
      if (prev) {
        prev.costUSD += e.costUSD;
        prev.inputTokens += e.inputTokens;
        prev.outputTokens += e.outputTokens;
        prev.cacheReadTokens += e.cacheReadTokens;
        prev.cacheWriteTokens += e.cacheWriteTokens;
      } else {
        combined.set(key, { ...e });
      }
    }
    return [...combined.values()];
  },
};
