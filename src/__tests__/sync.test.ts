/**
 * Tests for Phase 0.3: cloud policy sync + rules-cache enforcement.
 *
 * Covers:
 *  - readCredentials(): credentials.json profiles, env var, missing
 *  - getCloudSyncStatus() / getCloudRules(): reads cache file
 *  - runCloudSync(): returns error when no credentials
 *  - getConfig() cloud cache layer: merges rules-cache.json into policy
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Must be set before any module import that reads it
process.env.NODE9_TESTING = '1';

const MOCK_HOME = '/mock/home';
const CRED_PATH = path.join(MOCK_HOME, '.node9', 'credentials.json');
const CACHE_PATH = path.join(MOCK_HOME, '.node9', 'rules-cache.json');
const CONFIG_PATH = path.join(MOCK_HOME, '.node9', 'config.json');

// Spy once — vi.clearAllMocks() in afterEach resets call history without
// uninstalling the spy, so mockImplementation() keeps working across tests.
const existsSpy = vi.spyOn(fs, 'existsSync');
const readSpy = vi.spyOn(fs, 'readFileSync');
vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
const homeSpy = vi.spyOn(os, 'homedir');

import {
  runCloudSync,
  getCloudSyncStatus,
  getCloudRules,
} from '../daemon/sync.js';
import { getConfig, _resetConfigCache } from '../core.js';

// ── helpers ────────────────────────────────────────────────────────────────────

function mockFiles(files: Record<string, string>) {
  existsSpy.mockImplementation((p) => p.toString() in files);
  readSpy.mockImplementation((p: unknown) => {
    const content = files[p!.toString()];
    if (content === undefined) throw new Error(`ENOENT: ${String(p)}`);
    return content;
  });
}

beforeEach(() => {
  homeSpy.mockReturnValue(MOCK_HOME);
  _resetConfigCache();
  delete process.env.NODE9_API_KEY;
  delete process.env.NODE9_API_URL;
  delete process.env.NODE9_PROFILE;
  // Default: no files exist
  existsSpy.mockReturnValue(false);
  readSpy.mockImplementation(() => { throw new Error('ENOENT'); });
});

afterEach(() => {
  vi.clearAllMocks(); // clears call history, keeps spies installed
});

// ── runCloudSync — credentials resolution ─────────────────────────────────────

describe('runCloudSync — credentials resolution', () => {
  it('returns error when credentials.json is absent and no env var', async () => {
    mockFiles({});
    const result = await runCloudSync();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/No API key/i);
  });

  it('returns error when credentials.json has no apiKey', async () => {
    mockFiles({ [CRED_PATH]: JSON.stringify({ default: { apiUrl: 'https://example.com' } }) });
    const result = await runCloudSync();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/No API key/i);
  });

  it('reads apiKey from NODE9_API_KEY env var (network will fail — expected)', async () => {
    process.env.NODE9_API_KEY = 'test-key-from-env';
    mockFiles({});
    const result = await runCloudSync();
    // Should attempt a real fetch and fail with a network error, not "No API key"
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).not.toMatch(/No API key/i);
  });

  it('reads apiKey from credentials.json default profile (network will fail — expected)', async () => {
    mockFiles({
      [CRED_PATH]: JSON.stringify({
        default: {
          apiKey: 'n9_live_abc123',
          apiUrl: 'https://dev-api.node9.ai/api/v1/intercept',
        },
      }),
    });
    const result = await runCloudSync();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).not.toMatch(/No API key/i);
  });

  it('reads apiKey from a named profile in credentials.json (network will fail — expected)', async () => {
    process.env.NODE9_PROFILE = 'staging';
    mockFiles({
      [CRED_PATH]: JSON.stringify({
        default: { apiKey: 'default-key' },
        staging: { apiKey: 'staging-key', apiUrl: 'https://staging.node9.ai/api/v1/intercept' },
      }),
    });
    const result = await runCloudSync();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).not.toMatch(/No API key/i);
  });
});

// ── getCloudSyncStatus ─────────────────────────────────────────────────────────

describe('getCloudSyncStatus', () => {
  it('returns cached:false when cache file is absent', () => {
    mockFiles({});
    expect(getCloudSyncStatus()).toEqual({ cached: false });
  });

  it('returns cached:false when cache file is invalid JSON', () => {
    mockFiles({ [CACHE_PATH]: 'not-json{{{' });
    expect(getCloudSyncStatus()).toEqual({ cached: false });
  });

  it('returns cached:false when rules field is missing', () => {
    mockFiles({ [CACHE_PATH]: JSON.stringify({ fetchedAt: '2026-01-01T00:00:00.000Z' }) });
    expect(getCloudSyncStatus()).toEqual({ cached: false });
  });

  it('returns cached:true with rule count and fetchedAt', () => {
    const fetchedAt = '2026-04-16T10:00:00.000Z';
    mockFiles({
      [CACHE_PATH]: JSON.stringify({ fetchedAt, rules: [{ name: 'r1' }, { name: 'r2' }] }),
    });
    expect(getCloudSyncStatus()).toEqual({ cached: true, rules: 2, fetchedAt });
  });

  it('returns rules:0 for an empty rules array', () => {
    const fetchedAt = '2026-04-16T10:00:00.000Z';
    mockFiles({ [CACHE_PATH]: JSON.stringify({ fetchedAt, rules: [] }) });
    expect(getCloudSyncStatus()).toEqual({ cached: true, rules: 0, fetchedAt });
  });
});

// ── getCloudRules ─────────────────────────────────────────────────────────────

describe('getCloudRules', () => {
  it('returns null when cache file is absent', () => {
    mockFiles({});
    expect(getCloudRules()).toBeNull();
  });

  it('returns null when rules field is not an array', () => {
    mockFiles({
      [CACHE_PATH]: JSON.stringify({ fetchedAt: '2026-04-16T00:00:00.000Z', rules: 'bad' }),
    });
    expect(getCloudRules()).toBeNull();
  });

  it('returns the rules array', () => {
    const rules = [{ name: 'cloud-block', verdict: 'block' }];
    mockFiles({
      [CACHE_PATH]: JSON.stringify({ fetchedAt: '2026-04-16T00:00:00.000Z', rules }),
    });
    expect(getCloudRules()).toEqual(rules);
  });
});

// ── getConfig — cloud cache layer ─────────────────────────────────────────────

describe('getConfig — cloud rules cache layer', () => {
  it('merges cloud rules from rules-cache.json into policy', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }),
      [CACHE_PATH]: JSON.stringify({
        fetchedAt: '2026-04-16T00:00:00.000Z',
        rules: [
          {
            name: 'cloud-no-drop',
            verdict: 'block',
            conditions: [{ field: 'command', op: 'matches', pattern: 'DROP TABLE' }],
          },
        ],
      }),
    });
    const config = getConfig();
    const cloudRule = config.policy.smartRules.find((r) => r.name === 'cloud-no-drop');
    expect(cloudRule).toBeDefined();
    expect(cloudRule?.verdict).toBe('block');
  });

  it('cloud rule overrides local rule with same name (cloud wins — applied after local)', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({
        settings: { mode: 'standard' },
        policy: {
          smartRules: [
            {
              name: 'my-rule',
              verdict: 'review',
              conditions: [{ field: 'command', op: 'matches', pattern: 'foo' }],
            },
          ],
        },
      }),
      [CACHE_PATH]: JSON.stringify({
        fetchedAt: '2026-04-16T00:00:00.000Z',
        rules: [
          {
            name: 'my-rule',
            verdict: 'block',
            conditions: [{ field: 'command', op: 'matches', pattern: 'foo' }],
          },
        ],
      }),
    });
    const config = getConfig();
    const matches = config.policy.smartRules.filter((r) => r.name === 'my-rule');
    expect(matches).toHaveLength(1);
    expect(matches[0].verdict).toBe('block');
  });

  it('falls back gracefully when rules-cache.json is absent', () => {
    mockFiles({ [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }) });
    expect(() => getConfig()).not.toThrow();
  });

  it('falls back gracefully when rules-cache.json is corrupted', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }),
      [CACHE_PATH]: 'not-json{{{',
    });
    expect(() => getConfig()).not.toThrow();
  });

  it('cloudSyncIntervalHours defaults to 5', () => {
    mockFiles({ [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }) });
    expect(getConfig().settings.cloudSyncIntervalHours).toBe(5);
  });

  it('cloudSyncIntervalHours is configurable via config.json', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({
        settings: { mode: 'standard', cloudSyncIntervalHours: 12 },
      }),
    });
    expect(getConfig().settings.cloudSyncIntervalHours).toBe(12);
  });
});
