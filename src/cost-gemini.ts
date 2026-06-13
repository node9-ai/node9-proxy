// src/cost-gemini.ts
// cost-multi-agent Phase 1 — Gemini cost source (UPLOAD path).
//
// Gemini CLI journals live at ~/.gemini/tmp/<project>/chats/session-*.jsonl.
// Line 1 is session meta { sessionId, projectHash, startTime, ... }; each turn
// is { id, timestamp, type:'gemini'|'user'|'info', model?, tokens?:{ input,
// output, cached, thoughts, tool, total } }.
//
// Quirks (mirrored from the local reader in cli/aggregate/report-audit.ts so
// the upload and dashboard agree — see doc/cost-multi-agent-sources.md Phase 4):
//   - Each gemini turn is written TWICE with identical id+tokens → dedup by id.
//   - tokens.input INCLUDES tokens.cached → bill (input-cached) at the input
//     rate, cached at cache-read. thoughts/tool tokens are not billed here.
//   - Preview models missing from LiteLLM fall back to a same-tier proxy.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { pricingFor, normalizeModel } from './pricing/litellm.js';
import type { CostSource, DailyEntry } from './costSync.js';

export function geminiTmpDir(): string {
  return path.join(os.homedir(), '.gemini', 'tmp');
}

const GEMINI_FALLBACK_MODELS = ['gemini-2.5-flash', 'gemini-2.0-flash'];
function geminiPriceFor(
  model: string
): { input: number; output: number; cacheRead: number } | null {
  let tuple = pricingFor(model);
  if (!tuple && /^gemini-/i.test(model)) {
    for (const proxy of GEMINI_FALLBACK_MODELS) {
      tuple = pricingFor(proxy);
      if (tuple) break;
    }
  }
  if (!tuple) return null;
  return { input: tuple[0], output: tuple[1], cacheRead: tuple[3] || tuple[0] };
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

// ~/.gemini/tmp/<project>/chats/session-*.jsonl → [{ file, project }]
function listGeminiSessionFiles(base: string): Array<{ file: string; project: string }> {
  const out: Array<{ file: string; project: string }> = [];
  for (const project of safeReaddir(base)) {
    const chats = path.join(base, project, 'chats');
    if (!isDir(chats)) continue;
    for (const f of safeReaddir(chats)) {
      if (f.startsWith('session-') && f.endsWith('.jsonl')) {
        out.push({ file: path.join(chats, f), project });
      }
    }
  }
  return out;
}

interface GeminiTurn {
  id?: string;
  timestamp?: string;
  model?: string;
  tokens?: { input?: number; output?: number; cached?: number };
}

/**
 * Parse one gemini session file into DailyEntry[] (one per date+model in the
 * file, keyed within the session). `project` becomes the workingDir label and
 * `runId` the session id. Pure — exported for unit tests.
 */
export function parseGeminiSession(lines: string[], project: string): DailyEntry[] {
  const seenIds = new Set<string>();
  const byKey = new Map<string, DailyEntry>();
  let runId = '';

  for (const raw of lines) {
    if (!raw.trim()) continue;
    let obj: GeminiTurn & { sessionId?: string };
    try {
      obj = JSON.parse(raw) as typeof obj;
    } catch {
      continue;
    }
    if (typeof obj.sessionId === 'string' && !runId) runId = obj.sessionId;
    if (!obj.tokens || !obj.model || !obj.timestamp) continue;
    if (obj.id) {
      if (seenIds.has(obj.id)) continue; // dedup the double-write
      seenIds.add(obj.id);
    }
    const price = geminiPriceFor(obj.model);
    if (!price) continue;

    const inp = obj.tokens.input ?? 0;
    const out = obj.tokens.output ?? 0;
    const cached = Math.min(obj.tokens.cached ?? 0, inp);
    const fresh = Math.max(0, inp - cached);
    const cost = fresh * price.input + cached * price.cacheRead + out * price.output;

    const date = obj.timestamp.slice(0, 10);
    const model = normalizeModel(obj.model);
    const key = `${date}::${model}`;
    const prev = byKey.get(key);
    if (prev) {
      prev.costUSD += cost;
      prev.inputTokens += fresh;
      prev.outputTokens += out;
      prev.cacheReadTokens += cached;
    } else {
      byKey.set(key, {
        date,
        model,
        workingDir: project,
        runId,
        costUSD: cost,
        inputTokens: fresh,
        outputTokens: out,
        cacheReadTokens: cached,
        cacheWriteTokens: 0,
      });
    }
  }
  // Backfill runId (often only on the meta line, read after some turns).
  if (runId) for (const e of byKey.values()) e.runId = runId;
  return [...byKey.values()];
}

export const geminiSource: CostSource = {
  id: 'gemini',
  available(): boolean {
    try {
      return fs.existsSync(geminiTmpDir());
    } catch {
      return false;
    }
  },
  collect(sinceMs?: number): DailyEntry[] {
    const combined = new Map<string, DailyEntry>();
    for (const { file, project } of listGeminiSessionFiles(geminiTmpDir())) {
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
      for (const e of parseGeminiSession(content.split('\n'), project)) {
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
