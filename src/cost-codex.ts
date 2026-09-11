// Codex usage is cumulative within a counter epoch, but models and days belong
// to individual requests. All local readers and uploads use this parser.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { pricingFor, normalizeModel } from './pricing/litellm.js';
import type { CostSource, DailyEntry } from './costSync.js';

export function codexSessionsDir(): string {
  return path.join(process.env.CODEX_HOME?.trim() || path.join(os.homedir(), '.codex'), 'sessions');
}

const CODEX_FALLBACK: readonly [number, number, number, number] = [5e-6, 15e-6, 0, 2.5e-6];

export function codexPriceFor(model: string): readonly [number, number, number, number] {
  // A dated snapshot may use its family's rate, but gpt-5.4-mini must never
  // silently inherit gpt-5 rates just because the identifiers share a prefix.
  return pricingFor(codexModel(model), { exact: true }) ?? CODEX_FALLBACK;
}

function codexModel(model: string): string {
  return normalizeModel(model.replace(/^openai\//i, '').replace(/-\d{4}-\d{2}-\d{2}$/, ''));
}

type CodexTokens = { input: number; cached: number; output: number; cacheWrite: number };

function addTokens(previous: CodexTokens | null, delta: CodexTokens): CodexTokens {
  return {
    input: (previous?.input ?? 0) + delta.input,
    cached: (previous?.cached ?? 0) + delta.cached,
    output: (previous?.output ?? 0) + delta.output,
    cacheWrite: (previous?.cacheWrite ?? 0) + delta.cacheWrite,
  };
}

/** Price one usage increment. Reasoning is already included in output. */
export function codexSessionCost(
  model: string,
  tokens: { input: number; cached: number; output: number; cacheWrite?: number },
  request?: { inputTokens: number; serviceTier?: string }
): number {
  const input = tokenNumber(tokens.input);
  const cached = Math.min(input, tokenNumber(tokens.cached));
  const written = Math.min(input - cached, tokenNumber(tokens.cacheWrite));
  const [pin, pout, pcw, pcr] = codexPriceFor(model || 'gpt-5');
  // These documented models apply the long-context rate to the whole request,
  // never to a session's cumulative input. Unknown models retain base estimates.
  // https://developers.openai.com/api/docs/models/gpt-6-astra
  const longContext =
    request &&
    request.inputTokens > 272_000 &&
    ['gpt-5.4', 'gpt-5.5', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-6-astra'].includes(
      codexModel(model)
    );
  const inputMultiplier = longContext ? 2 : 1;
  const outputMultiplier = longContext ? 1.5 : 1;
  // Service tier is often absent from rollouts. Do not infer Fast mode from
  // reasoning effort or from the user's current config (history may differ).
  const tierMultiplier =
    request?.serviceTier === 'flex'
      ? 0.5
      : codexModel(model) === 'gpt-6-astra' &&
          (request?.serviceTier === 'fast' || request?.serviceTier === 'priority')
        ? 2
        : 1;
  return (
    (((input - cached - written) * pin + cached * pcr + written * (pcw || pin)) * inputMultiplier +
      tokenNumber(tokens.output) * pout * outputMultiplier) *
    tierMultiplier
  );
}

/** Include archived rollouts; do not follow directory symlinks or read unrelated files. */
/**
 * A file's stats and its opening line, taken from ONE descriptor so the two
 * cannot describe different files if the rollout is rewritten mid-scan. Reads
 * only up to the first newline: a session's opening record is a few tens of KB
 * while the file itself can be hundreds of MB. A record larger than the cap
 * yields no id, which keeps that file independent rather than merging it with
 * another session.
 */
function statAndFirstLine(file: string): { stat: fs.Stats; first: string } {
  const CAP = 4 * 1024 * 1024;
  const CHUNK = 64 * 1024;
  const fd = fs.openSync(file, 'r');
  try {
    const stat = fs.fstatSync(fd);
    const limit = Math.min(stat.size, CAP);
    const parts: Buffer[] = [];
    for (let pos = 0; pos < limit; pos += CHUNK) {
      const buf = Buffer.alloc(Math.min(CHUNK, limit - pos));
      const read = fs.readSync(fd, buf, 0, buf.length, pos);
      if (read <= 0) break;
      const slice = buf.subarray(0, read);
      const nl = slice.indexOf(0x0a);
      // Decode only whole buffers, never a chunk boundary: a split multi-byte
      // character would corrupt the JSON we are about to parse.
      parts.push(nl >= 0 ? slice.subarray(0, nl) : slice);
      if (nl >= 0) break;
    }
    return { stat, first: Buffer.concat(parts).toString('utf8') };
  } finally {
    fs.closeSync(fd);
  }
}

export function listCodexSessionFiles(base = codexSessionsDir()): string[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const file = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(file);
        else if (entry.isFile() && entry.name.endsWith('.jsonl')) files.push(file);
      }
    } catch {
      /* missing or unreadable directory */
    }
  };
  walk(base);
  // Explicit test/custom roots remain isolated. Codex's archive is a sibling
  // of its standard sessions directory, including when CODEX_HOME is set.
  if (path.basename(base) === 'sessions') walk(path.join(path.dirname(base), 'archived_sessions'));
  // Moving/copying a rollout into the archive must not double its usage. The
  // newest copy of each session is authoritative; sessions with no id remain
  // independent. Use the same selection in upload, scan, report and sessions.
  const sessions = new Map<string, { file: string; mtime: number; size: number }>();
  for (const file of files.sort()) {
    try {
      const { stat, first: head } = statAndFirstLine(file);
      let id = '';
      try {
        const first = JSON.parse(head);
        if (first?.type === 'session_meta' && typeof first.payload?.id === 'string')
          id = first.payload.id;
      } catch {
        /* incomplete metadata; keep the file independently */
      }
      const key = id ? `session:${id}` : `file:${file}`;
      const prior = sessions.get(key);
      if (
        !prior ||
        stat.mtimeMs > prior.mtime ||
        (stat.mtimeMs === prior.mtime && stat.size > prior.size)
      ) {
        sessions.set(key, { file, mtime: stat.mtimeMs, size: stat.size });
      }
    } catch {
      /* file disappeared during discovery */
    }
  }
  return [...sessions.values()].map((s) => s.file);
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function tokenNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : 0;
}

function usage(value: unknown, fallback?: CodexTokens | null): CodexTokens | null {
  const u = record(value);
  if (!['input_tokens', 'output_tokens'].some((k) => typeof u[k] === 'number')) return null;
  // Reject malformed counters instead of treating them as a reset to zero.
  for (const key of [
    'input_tokens',
    'cached_input_tokens',
    'cache_read_input_tokens',
    'output_tokens',
    'cache_write_input_tokens',
  ]) {
    if (
      u[key] !== undefined &&
      (typeof u[key] !== 'number' || !Number.isFinite(u[key]) || (u[key] as number) < 0)
    )
      return null;
  }
  return {
    input: tokenNumber(u.input_tokens ?? fallback?.input),
    cached: tokenNumber(u.cached_input_tokens ?? u.cache_read_input_tokens ?? fallback?.cached),
    output: tokenNumber(u.output_tokens ?? fallback?.output),
    cacheWrite: tokenNumber(u.cache_write_input_tokens ?? fallback?.cacheWrite),
  };
}

function timestamp(value: unknown): string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value))
    ? new Date(value).toISOString()
    : '';
}

export type CodexUsageEvent = DailyEntry & { timestamp: string };
export type CodexUsage = {
  events: CodexUsageEvent[];
  sessionStart: string;
  runId: string;
  workingDir: string;
  legacyModels: string[];
};

/**
 * Consume the whole file before filtering a window so its opening baseline is
 * retained. Repeated totals are notifications, not new usage. Counter resets
 * start a new epoch; last_token_usage supplies that request when available.
 * Legacy logs without event timestamps fall back to session start.
 */
export function parseCodexUsage(lines: string[]): CodexUsage {
  const result: CodexUsage = {
    events: [],
    sessionStart: '',
    runId: '',
    workingDir: '',
    legacyModels: [],
  };
  let model = 'gpt-5';
  let serviceTier: string | undefined;
  let previous: CodexTokens | null = null;
  const legacyModels = new Set<string>();
  const seenStandalone = new Set<string>();

  for (const raw of lines) {
    let entry: Record<string, unknown>;
    try {
      entry = record(JSON.parse(raw));
    } catch {
      continue;
    }
    const p = record(entry.payload);
    if (entry.type === 'session_meta') {
      result.sessionStart ||= timestamp(p.timestamp ?? entry.timestamp);
      if (!result.runId && typeof p.id === 'string') result.runId = p.id;
      if (!result.workingDir && typeof p.cwd === 'string') result.workingDir = p.cwd;
      continue;
    }
    if (entry.type === 'turn_context') {
      if (typeof p.model === 'string' && p.model) {
        model = p.model;
        legacyModels.add(normalizeModel(model));
      }
      if (!result.workingDir && typeof p.cwd === 'string') result.workingDir = p.cwd;
      serviceTier = typeof p.service_tier === 'string' ? p.service_tier : undefined;
      continue;
    }
    if (entry.type !== 'event_msg' || p.type !== 'token_count') continue;
    const info = record(p.info);
    const total = usage(info.total_token_usage, previous);
    const last = usage(info.last_token_usage);
    if (!total && !last) continue;

    const eventModel = [info.model, info.model_name, p.model].find(
      (v) => typeof v === 'string' && v
    );
    if (typeof eventModel === 'string') model = eventModel;
    let delta: CodexTokens;
    if (total) {
      if (
        previous &&
        Object.keys(total).every(
          (k) => total[k as keyof CodexTokens] === previous![k as keyof CodexTokens]
        )
      )
        continue;
      const reset = previous && (total.input < previous.input || total.output < previous.output);
      delta = reset
        ? (last ?? total)
        : {
            input: Math.max(0, total.input - (previous?.input ?? 0)),
            cached: Math.max(0, total.cached - (previous?.cached ?? 0)),
            output: Math.max(0, total.output - (previous?.output ?? 0)),
            cacheWrite: Math.max(0, total.cacheWrite - (previous?.cacheWrite ?? 0)),
          };
      previous = total;
    } else {
      delta = last!;
      // With no cumulative counters, only identical timestamped records can
      // safely be deduplicated. Equal token counts alone can be real requests.
      const key = JSON.stringify([entry.timestamp, model, delta]);
      if (entry.timestamp && seenStandalone.has(key)) continue;
      if (entry.timestamp) seenStandalone.add(key);
      // Maintain the baseline when a stream temporarily omits total usage.
      previous = addTokens(previous, delta);
    }
    if (delta.input === 0 && delta.output === 0) continue;
    const ts = timestamp(entry.timestamp) || result.sessionStart;
    if (!ts) continue;
    const cached = Math.min(delta.input, delta.cached);
    const written = Math.min(delta.input - cached, delta.cacheWrite);
    result.events.push({
      timestamp: ts,
      date: ts.slice(0, 10),
      model: normalizeModel(model),
      workingDir: result.workingDir,
      runId: result.runId,
      costUSD: codexSessionCost(model, delta, {
        inputTokens: last?.input ?? delta.input,
        serviceTier: typeof info.service_tier === 'string' ? info.service_tier : serviceTier,
      }),
      inputTokens: delta.input - cached - written,
      outputTokens: delta.output,
      cacheReadTokens: cached,
      cacheWriteTokens: written,
    });
  }
  result.legacyModels = [...(legacyModels.size ? legacyModels : ['gpt-5'])];
  return result;
}

export function codexUsageInWindow(
  usage: CodexUsage,
  start?: Date | null,
  end?: Date
): CodexUsageEvent[] {
  return usage.events.filter(
    (e) =>
      (!start || Date.parse(e.timestamp) >= start.getTime()) &&
      (!end || Date.parse(e.timestamp) <= end.getTime())
  );
}

/** Daily/model rows, plus zeroes that overwrite obsolete legacy start-day rows. */
export function parseCodexSession(lines: string[]): DailyEntry[] {
  const parsed = parseCodexUsage(lines);
  if (!parsed.events.length) return [];
  const rows = new Map<string, DailyEntry>();
  if (parsed.sessionStart) {
    for (const model of parsed.legacyModels) {
      rows.set(`${parsed.sessionStart.slice(0, 10)}::${model}`, {
        date: parsed.sessionStart.slice(0, 10),
        model,
        workingDir: parsed.workingDir,
        runId: parsed.runId,
        costUSD: 0,
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      });
    }
  }
  for (const event of parsed.events) {
    const e: DailyEntry = {
      date: event.date,
      model: event.model,
      workingDir: event.workingDir,
      runId: event.runId,
      costUSD: event.costUSD,
      inputTokens: event.inputTokens,
      outputTokens: event.outputTokens,
      cacheReadTokens: event.cacheReadTokens,
      cacheWriteTokens: event.cacheWriteTokens,
    };
    const key = `${e.date}::${e.model}`;
    const prev = rows.get(key);
    if (!prev) rows.set(key, { ...e });
    else {
      prev.costUSD += e.costUSD;
      prev.inputTokens += e.inputTokens;
      prev.outputTokens += e.outputTokens;
      prev.cacheReadTokens += e.cacheReadTokens;
      prev.cacheWriteTokens += e.cacheWriteTokens;
    }
  }
  return [...rows.values()];
}

export const codexSource: CostSource = {
  id: 'codex',
  available: () =>
    fs.existsSync(codexSessionsDir()) ||
    fs.existsSync(path.join(path.dirname(codexSessionsDir()), 'archived_sessions')),
  collect(sinceMs?: number): DailyEntry[] {
    const entries: DailyEntry[] = [];
    for (const file of listCodexSessionFiles()) {
      try {
        if (sinceMs !== undefined && fs.statSync(file).mtimeMs < sinceMs) continue;
        entries.push(...parseCodexSession(fs.readFileSync(file, 'utf8').split('\n')));
      } catch {
        /* one unreadable rollout must not hide the rest */
      }
    }
    return entries;
  },
};
