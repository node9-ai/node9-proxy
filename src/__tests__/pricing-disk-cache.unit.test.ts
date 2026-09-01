// Regression: pricingFor read ONLY the async-primed memCache + the bundled
// snapshot — never the on-disk LiteLLM cache. So the synchronous `node9 report`
// CLI (which doesn't prime) fell back to bundled, where a model absent from the
// snapshot (e.g. gpt-5.4-mini) prefix-matches plain gpt-5 and is mispriced —
// while the cloud (primed) used the real rate. Manual testing against the cloud
// Report caught exactly this. pricingFor now reads the on-disk cache (the SAME
// table the cloud uses) once, synchronously, so local prices match the cloud.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { pricingFor, _resetPricingCache } from '../pricing/litellm';

let tmpHome: string;

beforeEach(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-pricing-disk-'));
  vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
  _resetPricingCache();
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetPricingCache();
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

function writeCache(prices: Record<string, [number, number, number, number]>, ageMs = 0): void {
  const dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'model-pricing.json'),
    JSON.stringify({ fetchedAt: new Date(Date.now() - ageMs).toISOString(), prices })
  );
}

function cacheFile(): string {
  return path.join(tmpHome, '.node9', 'model-pricing.json');
}

describe('pricingFor — reads the on-disk cache on the sync path (local == cloud)', () => {
  it('uses the disk rate for a cache-only model (gpt-5.4-mini), not the bundled gpt-5 prefix', () => {
    writeCache({ 'gpt-5.4-mini': [0.75e-6, 4.5e-6, 0, 0.075e-6] });
    const p = pricingFor('gpt-5.4-mini');
    expect(p).toEqual([0.75e-6, 4.5e-6, 0, 0.075e-6]);
    expect(p![0]).not.toBe(1.25e-6); // the bundled gpt-5 fallback ($1.25/M)
  });

  it('falls back to bundled gpt-5 when there is no disk cache', () => {
    const p = pricingFor('gpt-5.4-mini');
    expect(p![0]).toBe(1.25e-6); // bundled gpt-5 prefix match
  });

  it('USES a stale disk cache rather than reaching past it for something older', () => {
    // This used to assert the opposite, and that assertion was the bug.
    //
    // On 2026-09-01 the cache was 29h old — one TTL past. The sync CLI path
    // discarded it and fell back to BUNDLED_PRICING, a hand-maintained table
    // that stops at claude-opus-4-7. Every opus-5 and fable-5 row then priced
    // at nothing: 30 days of spend read $466 instead of $10,504. Same machine,
    // same data, same code, 95% of the money gone with no warning.
    //
    // A day-old LiteLLM snapshot is a slightly dated price. The bundled table
    // is a table that has never heard of the model. Preferring the second is
    // strictly worse, and the TTL should govern WHEN TO REFETCH, not whether
    // what we already have is usable.
    //
    // Safe because only ensurePricingLoaded (async — daemon and upload paths)
    // enforces the TTL, and it refetches when it trips. Fresh prices are
    // always on their way.
    writeCache({ 'gpt-5.4-mini': [0.75e-6, 4.5e-6, 0, 0.075e-6] }, 2 * 24 * 60 * 60 * 1000);
    const p = pricingFor('gpt-5.4-mini');
    expect(p![0]).toBe(0.75e-6); // the stale disk value, not bundled gpt-5
    expect(p![0]).not.toBe(1.25e-6);
  });

  it('still falls back to bundled when the cache is unreadable', () => {
    // Stale is usable; corrupt is not. The distinction has to survive.
    writeCache({ 'gpt-5.4-mini': [0.75e-6, 4.5e-6, 0, 0.075e-6] }, 0);
    fs.writeFileSync(cacheFile(), 'not json{{{');
    const p = pricingFor('gpt-5.4-mini');
    expect(p![0]).toBe(1.25e-6);
  });
});
