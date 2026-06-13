// src/cost-copilot.ts
// cost-multi-agent Phase 2 — GitHub Copilot CLI cost source (UPLOAD path).
//
// Copilot writes ~/.copilot/session-state/<sessionId>/events.jsonl. Unlike the
// other agents we don't reconstruct usage turn-by-turn: the `session.shutdown`
// event carries a PRE-AGGREGATED per-model rollup, cost included —
//   data.modelMetrics["<model>"] = {
//     requests: { cost, ... },
//     usage:    { inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens }
//   }
// `session.start` carries { sessionId, startTime, context:{ cwd } }.
//
// One DailyEntry per (model) in a finished session. We trust Copilot's own
// `requests.cost`; if absent (older/in-flight session) we price the tokens.
// See doc/cost-multi-agent-sources.md.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { pricingFor, normalizeModel } from './pricing/litellm.js';
import type { CostSource, DailyEntry } from './costSync.js';

export function copilotSessionsDir(): string {
  return path.join(os.homedir(), '.copilot', 'session-state');
}

function safeReaddir(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

interface ModelMetric {
  requests?: { cost?: number };
  usage?: {
    inputTokens?: number;
    outputTokens?: number;
    cacheReadTokens?: number;
    cacheWriteTokens?: number;
  };
}

function priceTokens(model: string, u: ModelMetric['usage']): number {
  const tuple = pricingFor(model);
  if (!tuple || !u) return 0;
  const [pin, pout, pcw, pcr] = tuple;
  return (
    (u.inputTokens ?? 0) * pin +
    (u.outputTokens ?? 0) * pout +
    (u.cacheWriteTokens ?? 0) * pcw +
    (u.cacheReadTokens ?? 0) * pcr
  );
}

/**
 * Parse one Copilot session's events into DailyEntry[] — one per model in the
 * session's final rollup. Empty until the session has shut down. Pure —
 * exported for unit tests.
 */
export function parseCopilotSession(lines: string[]): DailyEntry[] {
  let sessionId = '';
  let cwd = '';
  let startDate = '';
  let shutdownDate = '';
  let modelMetrics: Record<string, ModelMetric> | null = null;

  for (const raw of lines) {
    if (!raw.trim()) continue;
    let o: { type?: string; timestamp?: string; data?: Record<string, unknown> };
    try {
      o = JSON.parse(raw) as typeof o;
    } catch {
      continue;
    }
    const d = (o.data ?? {}) as Record<string, unknown>;
    if (o.type === 'session.start') {
      if (typeof d['sessionId'] === 'string') sessionId = d['sessionId'];
      if (typeof d['startTime'] === 'string') startDate = d['startTime'];
      const ctx = (d['context'] ?? {}) as Record<string, unknown>;
      if (typeof ctx['cwd'] === 'string') cwd = ctx['cwd'];
    } else if (o.type === 'session.shutdown') {
      if (d['modelMetrics'] && typeof d['modelMetrics'] === 'object') {
        modelMetrics = d['modelMetrics'] as Record<string, ModelMetric>;
      }
      if (typeof o.timestamp === 'string') shutdownDate = o.timestamp;
    }
  }

  if (!modelMetrics) return []; // no finished rollup → nothing to bill
  const date = (startDate || shutdownDate).slice(0, 10);
  if (!date) return [];

  const rows: DailyEntry[] = [];
  for (const [rawModel, m] of Object.entries(modelMetrics)) {
    const u = m.usage ?? {};
    const inputTokens = u.inputTokens ?? 0;
    const outputTokens = u.outputTokens ?? 0;
    const cacheReadTokens = u.cacheReadTokens ?? 0;
    const cacheWriteTokens = u.cacheWriteTokens ?? 0;
    if (
      inputTokens === 0 &&
      outputTokens === 0 &&
      cacheReadTokens === 0 &&
      cacheWriteTokens === 0
    ) {
      continue; // model present but unused
    }
    const model = normalizeModel(rawModel);
    // Trust Copilot's own cost; fall back to pricing the tokens.
    const costUSD =
      typeof m.requests?.cost === 'number' && m.requests.cost > 0
        ? m.requests.cost
        : priceTokens(rawModel, u);
    rows.push({
      date,
      model,
      workingDir: cwd,
      runId: sessionId,
      costUSD,
      inputTokens,
      outputTokens,
      cacheReadTokens,
      cacheWriteTokens,
    });
  }
  return rows;
}

export const copilotSource: CostSource = {
  id: 'copilot',
  available(): boolean {
    try {
      return fs.existsSync(copilotSessionsDir());
    } catch {
      return false;
    }
  },
  collect(sinceMs?: number): DailyEntry[] {
    const base = copilotSessionsDir();
    const combined = new Map<string, DailyEntry>();
    for (const sid of safeReaddir(base)) {
      const file = path.join(base, sid, 'events.jsonl');
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
      for (const e of parseCopilotSession(content.split('\n'))) {
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
    }
    return [...combined.values()];
  },
};
