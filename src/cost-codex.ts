// src/cost-codex.ts
// GAP-3 Phase 2 — Codex cost source.
//
// Codex emits per-turn token usage as an OpenTelemetry span, persisted both in
// ~/.codex/logs_2.sqlite and ~/.codex/log/codex-tui.log. We parse the LOG (plain
// fs + regex) rather than the SQLite DB: it carries the identical span, avoids a
// node:sqlite dependency (Node-version + dual-CJS/ESM-build fragility, and the
// repo's no-require lint rule), and is trivially testable. Full-history SQLite
// reading is a possible future enhancement.
//
// Normalization (why an adapter is needed — Codex reports usage unlike Claude):
//   Codex `input_tokens` INCLUDES cached. To avoid charging cached tokens at the
//   full input rate, we map non_cached_input_tokens → inputTokens (full rate) and
//   cached_input_tokens → cacheReadTokens. OpenAI has no Anthropic-style cache
//   write → cacheWriteTokens = 0. output_tokens already includes reasoning.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { pricingFor, normalizeModel } from './pricing/litellm.js';
import type { CostSource, DailyEntry } from './costSync.js';

function codexLogPath(): string {
  return path.join(os.homedir(), '.codex', 'log', 'codex-tui.log');
}

// Regexes anchor on the `token_usage.` prefix so `input_tokens=` inside
// `non_cached_input_tokens=` / `cached_input_tokens=` is never mis-captured.
const RE_INPUT = /token_usage\.input_tokens=(\d+)/;
const RE_CACHED = /token_usage\.cached_input_tokens=(\d+)/;
const RE_NON_CACHED = /token_usage\.non_cached_input_tokens=(\d+)/;
const RE_OUTPUT = /token_usage\.output_tokens=(\d+)/;
const RE_MODEL = /\bmodel=([^\s}]+)/;
const RE_THREAD = /\bthread\.id=([0-9a-fA-F-]+)/;
const RE_DATE = /^(\d{4}-\d{2}-\d{2})T/;

/**
 * Parse one codex-tui.log line into a DailyEntry, or null if it isn't a
 * token-usage line (or lacks a timestamp/model). Pure — exported for unit tests.
 */
export function parseCodexUsageLine(line: string): DailyEntry | null {
  if (!line.includes('token_usage')) return null;
  const date = line.match(RE_DATE)?.[1];
  if (!date) return null;
  const model = line.match(RE_MODEL)?.[1];
  if (!model) return null;

  const num = (re: RegExp): number => {
    const m = line.match(re);
    return m ? Number(m[1]) : 0;
  };
  const totalInput = num(RE_INPUT);
  const cached = num(RE_CACHED);
  const nonCached = num(RE_NON_CACHED);
  const output = num(RE_OUTPUT);

  // Full-rate input = non_cached when present; fall back to (total - cached).
  const inputTokens = nonCached || Math.max(0, totalInput - cached);
  if (inputTokens === 0 && output === 0 && cached === 0) return null; // no real usage

  const runId = line.match(RE_THREAD)?.[1] ?? '';
  const norm = normalizeModel(model);
  const p = pricingFor(model); // [in, out, cacheWrite, cacheRead]
  const costUSD = p ? inputTokens * p[0] + output * p[1] + cached * p[3] : 0;

  return {
    date,
    model: norm,
    workingDir: '', // Codex span carries no cwd — attribution is by runId (thread)
    runId,
    costUSD,
    inputTokens,
    outputTokens: output,
    cacheReadTokens: cached,
    cacheWriteTokens: 0,
  };
}

export const codexSource: CostSource = {
  id: 'codex',
  available(): boolean {
    try {
      return fs.existsSync(codexLogPath());
    } catch {
      return false;
    }
  },
  collect(sinceMs?: number): DailyEntry[] {
    const file = codexLogPath();
    let content: string;
    try {
      // Whole-file mtime cutoff (cheap). The log is appended continuously, so a
      // recent cutoff rarely skips it; per-line filtering below is the precise gate.
      if (sinceMs !== undefined && fs.statSync(file).mtimeMs < sinceMs) return [];
      content = fs.readFileSync(file, 'utf8');
    } catch {
      return [];
    }

    const combined = new Map<string, DailyEntry>();
    for (const line of content.split('\n')) {
      if (!line.includes('token_usage')) continue;
      // Per-line timestamp cutoff (the log spans many days in one file).
      if (sinceMs !== undefined) {
        const tsFull = line.match(/^(\S+)\s/)?.[1];
        if (tsFull) {
          const t = Date.parse(tsFull);
          if (!Number.isNaN(t) && t < sinceMs) continue;
        }
      }
      const e = parseCodexUsageLine(line);
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
