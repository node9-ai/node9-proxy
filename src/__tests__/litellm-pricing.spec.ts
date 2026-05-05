// Tests for src/pricing/litellm.ts.
//
// Strategy: real fs in a tmpdir for the cache file; fetch is mocked at
// the global fetch level. Each test isolates HOME so cache writes don't
// pollute the dev's actual ~/.node9.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  ensurePricingLoaded,
  pricingFor,
  normalizeModel,
  fetchLiteLLMPricing,
  tupleFromLiteLLM,
  _resetPricingCache,
  _bundledPricing,
} from '../pricing/litellm';

let tmpHome: string;
let originalHome: string | undefined;
let originalUserProfile: string | undefined;
let originalFetch: typeof fetch;

beforeEach(() => {
  originalHome = process.env.HOME;
  originalUserProfile = process.env.USERPROFILE;
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-pricing-'));
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });

  originalFetch = globalThis.fetch;
  _resetPricingCache();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  if (originalUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = originalUserProfile;
  globalThis.fetch = originalFetch;
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
  _resetPricingCache();
});

// ── normalizeModel ──────────────────────────────────────────────────────

describe('normalizeModel', () => {
  it('strips Anthropic date suffix', () => {
    expect(normalizeModel('claude-sonnet-4-20251101')).toBe('claude-sonnet-4');
  });

  it('lowercases input for cache-friendly keys', () => {
    expect(normalizeModel('Claude-Opus-4-7')).toBe('claude-opus-4-7');
  });

  it('passes a clean ID through unchanged', () => {
    expect(normalizeModel('gpt-4o-mini')).toBe('gpt-4o-mini');
  });
});

// ── tupleFromLiteLLM ────────────────────────────────────────────────────

describe('tupleFromLiteLLM', () => {
  it('builds a [in, out, cw, cr] tuple from the LiteLLM JSON shape', () => {
    expect(
      tupleFromLiteLLM({
        input_cost_per_token: 3e-6,
        output_cost_per_token: 15e-6,
        cache_creation_input_token_cost: 3.75e-6,
        cache_read_input_token_cost: 0.3e-6,
        litellm_provider: 'anthropic',
      })
    ).toEqual([3e-6, 15e-6, 3.75e-6, 0.3e-6]);
  });

  it('returns null when both input and output costs are absent', () => {
    expect(tupleFromLiteLLM({ litellm_provider: 'foo' })).toBeNull();
  });

  it('returns null for non-object input', () => {
    expect(tupleFromLiteLLM(null)).toBeNull();
    expect(tupleFromLiteLLM('not-json')).toBeNull();
  });

  it('coerces non-finite numerics to 0 (defensive)', () => {
    const t = tupleFromLiteLLM({
      input_cost_per_token: 5e-6,
      output_cost_per_token: 'not-a-number',
      cache_creation_input_token_cost: -1, // negative ignored
      cache_read_input_token_cost: Infinity,
    });
    expect(t).toEqual([5e-6, 0, 0, 0]);
  });
});

// ── pricingFor (uses bundled fallback when nothing else loaded) ─────────

describe('pricingFor — bundled fallback path', () => {
  it('returns bundled pricing for a known Claude model', () => {
    const tuple = pricingFor('claude-sonnet-4');
    expect(tuple).not.toBeNull();
    expect(tuple![0]).toBeGreaterThan(0); // input cost
    expect(tuple![1]).toBeGreaterThan(tuple![0]); // output > input
  });

  it('matches by longest-prefix when an exact key is missing', () => {
    // claude-sonnet-4-99-20300101 is unknown — should match claude-sonnet-4
    const tuple = pricingFor('claude-sonnet-4-99-20300101');
    expect(tuple).not.toBeNull();
    // Should match the same tuple as the prefix
    expect(tuple).toEqual(pricingFor('claude-sonnet-4'));
  });

  it('returns null for a completely unknown model', () => {
    expect(pricingFor('totally-unknown-model-xyz')).toBeNull();
  });

  it('lower-cases input for case-insensitive lookup', () => {
    expect(pricingFor('CLAUDE-OPUS-4')).not.toBeNull();
  });
});

// ── ensurePricingLoaded — cache hit path ───────────────────────────────

describe('ensurePricingLoaded — cache hit', () => {
  it('reads a fresh cache file without fetching', async () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'model-pricing.json'),
      JSON.stringify({
        fetchedAt: new Date().toISOString(),
        prices: { 'cached-model': [1e-6, 2e-6, 0, 0] },
      })
    );

    // No fetch should happen — fail loud if it does.
    globalThis.fetch = vi.fn(async () => {
      throw new Error('fetch should not be called when cache is fresh');
    }) as unknown as typeof fetch;

    await ensurePricingLoaded();
    expect(pricingFor('cached-model')).toEqual([1e-6, 2e-6, 0, 0]);
  });

  it('ignores an expired cache (>1 day old) and falls through', async () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'model-pricing.json'),
      JSON.stringify({
        // 2 days old — past the TTL.
        fetchedAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
        prices: { 'stale-model': [9e-6, 9e-6, 0, 0] },
      })
    );
    // Fetch fails too → falls back to bundled snapshot.
    globalThis.fetch = vi.fn(async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch;

    await ensurePricingLoaded();
    // Stale cache should NOT be used.
    expect(pricingFor('stale-model')).toBeNull();
    // Bundled fallback still works.
    expect(pricingFor('claude-sonnet-4')).not.toBeNull();
  });
});

// ── ensurePricingLoaded — fetch path ───────────────────────────────────

describe('ensurePricingLoaded — fetch path', () => {
  it('fetches from LiteLLM, caches, and uses the result', async () => {
    // LiteLLM returns 600+ models in real life. We simulate a small but
    // valid sample (>= 10 entries to clear the schema-drift guard).
    const sample: Record<string, unknown> = {};
    for (let i = 0; i < 12; i++) {
      sample[`model-${i}`] = {
        input_cost_per_token: i * 1e-6,
        output_cost_per_token: i * 2e-6,
        cache_creation_input_token_cost: 0,
        cache_read_input_token_cost: 0,
      };
    }
    globalThis.fetch = vi.fn(
      async () =>
        new Response(JSON.stringify(sample), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
    ) as unknown as typeof fetch;

    await ensurePricingLoaded();
    const tuple = pricingFor('model-5');
    expect(tuple).not.toBeNull();
    // Floating-point arithmetic ('5 * 1e-6' ≠ '5e-6' bit-exactly), so
    // assert near-equality rather than strict deep-equal.
    expect(tuple![0]).toBeCloseTo(5 * 1e-6, 12);
    expect(tuple![1]).toBeCloseTo(5 * 2e-6, 12);
    expect(tuple![2]).toBe(0);
    expect(tuple![3]).toBe(0);

    // Cache file written.
    const cachePath = path.join(tmpHome, '.node9', 'model-pricing.json');
    expect(fs.existsSync(cachePath)).toBe(true);
    const cached = JSON.parse(fs.readFileSync(cachePath, 'utf-8'));
    expect(typeof cached.fetchedAt).toBe('string');
    expect(cached.prices['model-5']).toBeDefined();
  });

  it('falls back to bundled snapshot when fetch returns a tiny payload (schema-drift guard)', async () => {
    // Only 3 entries — below the 10-entry threshold. Real LiteLLM has 600+.
    globalThis.fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            a: { input_cost_per_token: 1e-6, output_cost_per_token: 2e-6 },
            b: { input_cost_per_token: 1e-6, output_cost_per_token: 2e-6 },
            c: { input_cost_per_token: 1e-6, output_cost_per_token: 2e-6 },
          }),
          { status: 200 }
        )
    ) as unknown as typeof fetch;

    await ensurePricingLoaded();
    // Suspicious payload not used.
    expect(pricingFor('a')).toBeNull();
    // Bundled fallback works.
    expect(pricingFor('claude-sonnet-4')).not.toBeNull();
  });

  it('falls back to bundled snapshot when LiteLLM returns 500', async () => {
    globalThis.fetch = vi.fn(
      async () => new Response('Internal Server Error', { status: 500 })
    ) as unknown as typeof fetch;
    await ensurePricingLoaded();
    expect(pricingFor('claude-sonnet-4')).not.toBeNull();
  });

  it('falls back to bundled snapshot when fetch rejects (offline)', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error('ENETUNREACH');
    }) as unknown as typeof fetch;
    await ensurePricingLoaded();
    expect(pricingFor('claude-sonnet-4')).not.toBeNull();
  });
});

// ── fetchLiteLLMPricing — direct ───────────────────────────────────────

describe('fetchLiteLLMPricing direct', () => {
  it('returns null on a non-200 response', async () => {
    globalThis.fetch = vi.fn(
      async () => new Response('not found', { status: 404 })
    ) as unknown as typeof fetch;
    expect(await fetchLiteLLMPricing()).toBeNull();
  });

  it('returns null when JSON is malformed', async () => {
    globalThis.fetch = vi.fn(
      async () => new Response('not-json{{{', { status: 200 })
    ) as unknown as typeof fetch;
    expect(await fetchLiteLLMPricing()).toBeNull();
  });
});

// ── _bundledPricing — sanity ────────────────────────────────────────────

describe('_bundledPricing', () => {
  it('contains at least one Claude and one OpenAI model', () => {
    const b = _bundledPricing();
    const keys = Object.keys(b);
    expect(keys.some((k) => k.startsWith('claude-'))).toBe(true);
    expect(keys.some((k) => k.startsWith('gpt-'))).toBe(true);
  });

  it('every tuple has 4 non-negative numbers', () => {
    const b = _bundledPricing();
    for (const [model, tuple] of Object.entries(b)) {
      expect(tuple).toHaveLength(4);
      for (const v of tuple) {
        expect(v).toBeGreaterThanOrEqual(0);
        expect(Number.isFinite(v)).toBe(true);
      }
      // Every model must have at least input+output > 0
      expect(tuple[0] + tuple[1]).toBeGreaterThan(0);
      // Sanity: keep `model` referenced so a future bad entry survives lint
      expect(typeof model).toBe('string');
    }
  });
});
