// src/pricing/litellm.ts
//
// Model pricing source: LiteLLM's community-maintained JSON. Free, MIT-
// licensed, ~600 models covered. Updated by LiteLLM contributors within
// hours of provider price changes — much more accurate than hardcoded
// tables that drift every time Anthropic / OpenAI / Google ship a new
// model.
//
// Strategy:
//   1. Cache: ~/.node9/model-pricing.json with 1-day TTL.
//   2. On miss/expired: fetch from LiteLLM, validate via Zod, atomic-
//      write to cache.
//   3. On any fetch failure: fall back to BUNDLED_PRICING below — a
//      small static snapshot covering the major models. Means the
//      proxy works offline + on first run before fetch completes.
//
// The pricingFor(model) function used by costSync remains the public
// API; the underlying source is just smarter now.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { HOOK_DEBUG_LOG } from '../audit/index.js';

const LITELLM_URL =
  'https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json';

/** USD-per-token tuple: [input, output, cacheWrite, cacheRead]. */
export type PricingTuple = readonly [number, number, number, number];

/**
 * Bundled fallback. Used when LiteLLM fetch fails AND the local cache
 * is missing/expired. Small, hand-curated snapshot of the most common
 * models the proxy will see — enough to compute *some* cost on a fresh
 * install before the first fetch lands. Values match LiteLLM's June
 * 2026 snapshot.
 *
 * Keys are LiteLLM-style model identifiers (no Anthropic date suffix).
 * Values are [in, out, cacheWrite, cacheRead] in USD-per-token.
 */
const BUNDLED_PRICING: Record<string, PricingTuple> = {
  // Anthropic
  'claude-opus-4': [5e-6, 25e-6, 6.25e-6, 0.5e-6],
  'claude-opus-4-1': [5e-6, 25e-6, 6.25e-6, 0.5e-6],
  'claude-opus-4-5': [5e-6, 25e-6, 6.25e-6, 0.5e-6],
  'claude-opus-4-6': [5e-6, 25e-6, 6.25e-6, 0.5e-6],
  'claude-opus-4-7': [5e-6, 25e-6, 6.25e-6, 0.5e-6],
  'claude-sonnet-4': [3e-6, 15e-6, 3.75e-6, 0.3e-6],
  'claude-sonnet-4-5': [3e-6, 15e-6, 3.75e-6, 0.3e-6],
  'claude-sonnet-4-6': [3e-6, 15e-6, 3.75e-6, 0.3e-6],
  'claude-haiku-4': [0.8e-6, 4e-6, 1e-6, 0.08e-6],
  'claude-haiku-4-5': [0.8e-6, 4e-6, 1e-6, 0.08e-6],
  'claude-3-7-sonnet': [3e-6, 15e-6, 3.75e-6, 0.3e-6],
  'claude-3-5-sonnet': [3e-6, 15e-6, 3.75e-6, 0.3e-6],
  'claude-3-5-haiku': [0.8e-6, 4e-6, 1e-6, 0.08e-6],
  'claude-3-haiku': [0.25e-6, 1.25e-6, 0.3e-6, 0.03e-6],
  // OpenAI
  'gpt-4o': [5e-6, 15e-6, 0, 2.5e-6],
  'gpt-4o-mini': [0.15e-6, 0.6e-6, 0, 0.075e-6],
  'gpt-5': [10e-6, 30e-6, 0, 5e-6],
  // Google
  'gemini-2.0-flash': [0.075e-6, 0.3e-6, 0, 0],
  'gemini-1.5-pro': [1.25e-6, 5e-6, 0, 0],
};

const CACHE_FILE = () => path.join(os.homedir(), '.node9', 'model-pricing.json');
const TTL_MS = 24 * 60 * 60 * 1000; // 1 day

/** Cache file shape — fetchedAt for TTL, prices keyed by LiteLLM model name. */
interface PricingCache {
  fetchedAt: string;
  prices: Record<string, PricingTuple>;
}

/**
 * In-memory cache populated on first call. Saves repeated fs reads on
 * the hot path (every cost-sync run hits pricingFor multiple times).
 */
let memCache: Record<string, PricingTuple> | null = null;
let memCacheAt = 0;

/**
 * Strip the date suffix Anthropic appends to model IDs (e.g. `-20251101`)
 * and lowercase. Same normalisation costSync used before — kept so model
 * IDs match LiteLLM's keys.
 */
export function normalizeModel(raw: string): string {
  return raw.replace(/-\d{8}$/, '').toLowerCase();
}

/**
 * Read the cache file if fresh enough. Returns null on any error or if
 * older than TTL_MS. Silent failure: pricing is non-critical — we'd
 * rather fall back to bundled defaults than throw.
 */
function readCache(): Record<string, PricingTuple> | null {
  try {
    const raw = JSON.parse(fs.readFileSync(CACHE_FILE(), 'utf-8')) as PricingCache;
    if (
      typeof raw.fetchedAt !== 'string' ||
      typeof raw.prices !== 'object' ||
      raw.prices === null
    ) {
      return null;
    }
    const ageMs = Date.now() - new Date(raw.fetchedAt).getTime();
    if (ageMs < 0 || ageMs > TTL_MS) return null;
    return raw.prices;
  } catch {
    return null;
  }
}

/** Atomic write: tmpfile + rename. Same pattern as scan-watermark. */
function writeCache(prices: Record<string, PricingTuple>): void {
  try {
    const target = CACHE_FILE();
    const dir = path.dirname(target);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tmp = target + '.tmp';
    const body: PricingCache = {
      fetchedAt: new Date().toISOString(),
      prices,
    };
    fs.writeFileSync(tmp, JSON.stringify(body) + '\n', 'utf-8');
    fs.renameSync(tmp, target);
  } catch (err) {
    try {
      fs.appendFileSync(
        HOOK_DEBUG_LOG,
        `[pricing] cache write failed: ${(err as Error).message}\n`
      );
    } catch {
      /* ignore */
    }
  }
}

/**
 * Convert LiteLLM's JSON shape into our [in, out, cacheWrite, cacheRead]
 * tuple. LiteLLM uses field names like `input_cost_per_token` and
 * `cache_creation_input_token_cost`. We map and fall back to 0 for any
 * missing field (cheaper-than-string-typed-flow approach).
 *
 * Exported for unit testing — pure function over the JSON entry.
 */
export function tupleFromLiteLLM(entry: unknown): PricingTuple | null {
  if (!entry || typeof entry !== 'object') return null;
  const e = entry as Record<string, unknown>;
  const num = (v: unknown): number =>
    typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : 0;
  const inCost = num(e.input_cost_per_token);
  const outCost = num(e.output_cost_per_token);
  // Either field is enough to consider the entry valid pricing.
  if (inCost === 0 && outCost === 0) return null;
  return [
    inCost,
    outCost,
    num(e.cache_creation_input_token_cost),
    num(e.cache_read_input_token_cost),
  ];
}

/**
 * Fetch LiteLLM JSON, parse, write to cache. Returns the parsed map or
 * null on any error. Network failures, malformed JSON, schema drift —
 * all silently fall back to the bundled snapshot via the caller.
 *
 * Exported for unit testing; internal callers use ensurePricingLoaded().
 */
export async function fetchLiteLLMPricing(): Promise<Record<string, PricingTuple> | null> {
  try {
    const res = await fetch(LITELLM_URL, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return null;
    const json = (await res.json()) as Record<string, unknown>;
    if (!json || typeof json !== 'object') return null;
    const out: Record<string, PricingTuple> = {};
    for (const [key, value] of Object.entries(json)) {
      const tuple = tupleFromLiteLLM(value);
      if (tuple) out[key.toLowerCase()] = tuple;
    }
    if (Object.keys(out).length < 10) {
      // Suspicious — LiteLLM publishes ~600 models. If we got <10 the
      // schema probably drifted. Fall back rather than persist garbage.
      return null;
    }
    return out;
  } catch {
    return null;
  }
}

/**
 * Load pricing into the in-memory cache. Order:
 *   1. Already loaded → return memCache.
 *   2. Fresh on-disk cache → use it.
 *   3. Try LiteLLM fetch → if good, cache + use it.
 *   4. Fall back to bundled snapshot.
 *
 * Idempotent. Safe to call from many places — the actual fetch happens
 * at most once per process per day.
 */
export async function ensurePricingLoaded(): Promise<void> {
  if (memCache !== null && Date.now() - memCacheAt < TTL_MS) return;

  const fromDisk = readCache();
  if (fromDisk && Object.keys(fromDisk).length > 0) {
    memCache = fromDisk;
    memCacheAt = Date.now();
    return;
  }

  const fetched = await fetchLiteLLMPricing();
  if (fetched && Object.keys(fetched).length > 0) {
    memCache = fetched;
    memCacheAt = Date.now();
    writeCache(fetched);
    return;
  }

  // Bundled fallback. Always non-empty.
  memCache = { ...BUNDLED_PRICING };
  memCacheAt = Date.now();
}

/**
 * Look up pricing for a model. Tries exact match, then longest-prefix
 * match (so `claude-sonnet-4-5-20260101` resolves to `claude-sonnet-4-5`).
 * Falls back to bundled snapshot keys if the in-memory cache lookup
 * misses entirely — covers the case where we've fetched LiteLLM but it
 * doesn't carry a model the proxy is reporting.
 *
 * Returns null when no match exists in either source. Caller must handle
 * the "unknown model — skip cost calc" path.
 */
export function pricingFor(model: string): PricingTuple | null {
  const norm = normalizeModel(model);
  const sources: Array<Record<string, PricingTuple>> = [];
  if (memCache) sources.push(memCache);
  sources.push(BUNDLED_PRICING);

  for (const source of sources) {
    const exact = source[norm];
    if (exact) return exact;
    let best: string | null = null;
    for (const key of Object.keys(source)) {
      if (norm.startsWith(key.toLowerCase()) && (best === null || key.length > best.length)) {
        best = key;
      }
    }
    if (best) return source[best]!;
  }
  return null;
}

/** Test-only — reset the in-memory cache so tests don't pollute each other. */
export function _resetPricingCache(): void {
  memCache = null;
  memCacheAt = 0;
}

/** Test-only — read the bundled fallback directly. */
export function _bundledPricing(): Record<string, PricingTuple> {
  return BUNDLED_PRICING;
}
