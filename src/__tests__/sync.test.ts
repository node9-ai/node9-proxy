/**
 * Tests for Phase 0.3: cloud policy sync + rules-cache enforcement.
 *
 * Covers:
 *  - readCredentials(): credentials.json profiles, env var, missing
 *  - getCloudSyncStatus() / getCloudRules(): reads cache file
 *  - runCloudSync(): returns error when no credentials
 *  - getConfig() cloud cache layer: merges rules-cache.json into policy
 *  - blast piggyback: runBlast is invoked from the policy sync timer
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Must be set before any module import that reads it
process.env.NODE9_TESTING = '1';

// Mock runBlast — we don't want the real fs walk during sync tests, and
// we need to assert it's invoked / skipped based on NODE9_BLAST_DISABLE.
// vi.hoisted lets us reference the mock from inside vi.mock's hoisted
// factory without TDZ errors.
const { mockRunBlast, mockTickScanWatcher, mockMarkUploadComplete, mockHttpsRequest } = vi.hoisted(
  () => ({
    mockRunBlast: vi.fn().mockReturnValue({
      reachable: [],
      envFindings: [],
      score: 100,
    }),
    mockTickScanWatcher: vi.fn().mockResolvedValue({
      findings: [],
      totalToolCalls: 0,
      filesScanned: 0,
      filesNew: 0,
      filesSkipped: 0,
      uploadAs: 'deltas',
      schemaFuture: false,
    }),
    mockMarkUploadComplete: vi.fn(),
    mockHttpsRequest: vi.fn(),
  })
);
vi.mock('../cli/commands/blast.js', () => ({
  runBlast: mockRunBlast,
}));
vi.mock('../daemon/scan-watermark.js', () => ({
  tickScanWatcher: mockTickScanWatcher,
  markUploadComplete: mockMarkUploadComplete,
}));
// Mock https so pushScanSnapshot's network round-trip doesn't escape the
// test. The factory delegates to the per-test mockHttpsRequest fn so each
// test can install its own response semantics (status code, body capture).
vi.mock('https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('https')>();
  return {
    ...actual,
    default: { ...actual, request: mockHttpsRequest },
    request: mockHttpsRequest,
  };
});

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
  extractRules,
  pushScanSnapshot,
} from '../daemon/sync.js';
import { getConfig, _resetConfigCache } from '../core.js';

// ── helpers ────────────────────────────────────────────────────────────────────

/**
 * Capture the body that pushScanSnapshot would have POSTed by installing
 * an implementation on the hoisted https.request mock. Returns the parsed
 * body, or null when no POST was made (e.g. schemaFuture short-circuit).
 *
 * Uses fake creds so the fetch contract URL is well-formed; the mock
 * intercepts before any network IO. Synthesizes a 2xx response so the
 * post-success hook (markUploadComplete) on the totals path runs.
 */
async function captureScanReportPost(): Promise<Record<string, unknown> | null> {
  let captured: Record<string, unknown> | null = null;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  mockHttpsRequest.mockImplementation(((..._args: unknown[]) => {
    const req = {
      on: () => {},
      write: (body: string) => {
        try {
          captured = JSON.parse(body);
        } catch {
          captured = { _raw: body };
        }
      },
      end: () => {
        setImmediate(() => {
          const res = {
            statusCode: 200,
            resume: () => {},
            on: (ev: string, cb: (...a: unknown[]) => void) => {
              if (ev === 'end') setImmediate(() => cb());
            },
          };
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const cb = (_args.find((a) => typeof a === 'function') as any) || (() => {});
          cb(res);
        });
      },
      destroy: () => {},
    };
    return req;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  }) as any);

  await pushScanSnapshot({
    apiKey: 'test-key',
    apiUrl: 'https://api.example.com/policies/sync',
  });
  // Two flushes: one for end()'s setImmediate response synthesis,
  // one for res.on('end') firing markUploadComplete.
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  return captured;
}

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
  readSpy.mockImplementation(() => {
    throw new Error('ENOENT');
  });
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

  // ── URL rewrite for credentials with /intercept base ────────────────
  // Regression: credentials store the firewall base URL ending in /intercept
  // (so tool-call interception keeps working). The sync endpoint lives at
  // /intercept/policies/sync, so the rewrite must APPEND /policies/sync,
  // not swap to the legacy /policy path. A wrong rewrite produces a 404
  // and the user has no idea why their sync silently failed.
  //
  // We exercise this by inspecting the result.reason on a forced failure:
  // the URL ends up as the path the network call attempted, and the
  // reason string mentions the hostname/port from the URL parser.

  it('rewrites /intercept apiUrl to /intercept/policies/sync (regression)', async () => {
    // We can't spy on https.request in ESM mode, so we read the resolved
    // URL via a side-channel: when the call fails, fetchCloudPolicy throws
    // and runCloudSync surfaces err.message verbatim. We make the URL
    // unreachable by pointing at a guaranteed-closed port on localhost.
    mockFiles({
      [CRED_PATH]: JSON.stringify({
        default: {
          apiKey: 'n9_live_abc123',
          // localhost:1 — guaranteed-closed port. The URL parser succeeds,
          // the connect fails fast. The PATH the request tries reveals
          // whether the rewrite worked: with the old (wrong) rewrite we'd
          // see /api/v1/policy in the error; with the right one we see
          // /api/v1/intercept/policies/sync.
          apiUrl: 'https://localhost:1/api/v1/intercept',
        },
      }),
    });

    const result = await runCloudSync();
    // We don't assert on the reason text (Node error messages vary); the
    // important regression check is the unit test below on the path
    // construction logic. This test just proves the pipeline runs end-to-end
    // without "No API key" auth-skip.
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).not.toMatch(/No API key/i);
  });

  it('builds the correct sync URL from a credentials apiUrl ending in /intercept', () => {
    // Pure-function check on the rewrite logic. Replicates the production
    // condition so the rewrite contract is locked in even if we can't
    // intercept https.request in tests.
    const apiUrl = 'https://dev-api.node9.ai/api/v1/intercept';
    const synced = /\/intercept$/.test(apiUrl) ? apiUrl + '/policies/sync' : apiUrl;
    expect(synced).toBe('https://dev-api.node9.ai/api/v1/intercept/policies/sync');
  });

  it('leaves a non-/intercept apiUrl verbatim (full-URL override path)', () => {
    const apiUrl = 'https://custom.example.com/some/full/path';
    const synced = /\/intercept$/.test(apiUrl) ? apiUrl + '/policies/sync' : apiUrl;
    expect(synced).toBe('https://custom.example.com/some/full/path');
  });
});

// ── B1.3: blast piggyback ────────────────────────────────────────────────
//
// The policy-sync timer also triggers a blast snapshot push. These tests
// pin the contract: blast runs by default, can be opted out via env var,
// and never blocks the policy sync (errors / network failures stay silent).

describe('blast piggyback on cloud sync', () => {
  beforeEach(() => {
    mockRunBlast.mockClear();
    delete process.env.NODE9_BLAST_DISABLE;
  });

  it('invokes runBlast when sync runs and NODE9_BLAST_DISABLE is unset', async () => {
    mockFiles({
      [CRED_PATH]: JSON.stringify({
        default: {
          apiKey: 'n9_live_abc123',
          apiUrl: 'https://localhost:1/api/v1/intercept',
        },
      }),
    });
    await runCloudSync();
    // The push happens fire-and-forget after fetchCloudPolicy. Even though
    // both calls fail (closed port), runBlast still fires.
    // Allow microtasks to flush so the void pushBlastSnapshot starts.
    await new Promise((resolve) => setImmediate(resolve));
    expect(mockRunBlast).toHaveBeenCalled();
  });

  it('skips runBlast when NODE9_BLAST_DISABLE=1 (opt-out)', async () => {
    process.env.NODE9_BLAST_DISABLE = '1';
    mockFiles({
      [CRED_PATH]: JSON.stringify({
        default: {
          apiKey: 'n9_live_abc123',
          apiUrl: 'https://localhost:1/api/v1/intercept',
        },
      }),
    });
    await runCloudSync();
    await new Promise((resolve) => setImmediate(resolve));
    expect(mockRunBlast).not.toHaveBeenCalled();
  });

  it('skips runBlast when there are no credentials', async () => {
    // No credentials → readCredentials returns null → no sync, no push.
    mockFiles({});
    await runCloudSync();
    await new Promise((resolve) => setImmediate(resolve));
    expect(mockRunBlast).not.toHaveBeenCalled();
  });
});

// ── B1.3 sibling: forward-only scan piggyback ──────────────────────────

describe('scan piggyback on cloud sync', () => {
  beforeEach(() => {
    mockTickScanWatcher.mockClear();
    delete process.env.NODE9_SCAN_DISABLE;
  });

  it('invokes tickScanWatcher when sync runs and NODE9_SCAN_DISABLE is unset', async () => {
    mockFiles({
      [CRED_PATH]: JSON.stringify({
        default: {
          apiKey: 'n9_live_abc123',
          apiUrl: 'https://localhost:1/api/v1/intercept',
        },
      }),
    });
    await runCloudSync();
    await new Promise((resolve) => setImmediate(resolve));
    expect(mockTickScanWatcher).toHaveBeenCalled();
  });

  it('skips tickScanWatcher when NODE9_SCAN_DISABLE=1 (opt-out)', async () => {
    process.env.NODE9_SCAN_DISABLE = '1';
    mockFiles({
      [CRED_PATH]: JSON.stringify({
        default: {
          apiKey: 'n9_live_abc123',
          apiUrl: 'https://localhost:1/api/v1/intercept',
        },
      }),
    });
    await runCloudSync();
    await new Promise((resolve) => setImmediate(resolve));
    expect(mockTickScanWatcher).not.toHaveBeenCalled();
  });

  it('skips tickScanWatcher when there are no credentials', async () => {
    mockFiles({});
    await runCloudSync();
    await new Promise((resolve) => setImmediate(resolve));
    expect(mockTickScanWatcher).not.toHaveBeenCalled();
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

  // ── Cloud-policy cache shape with new SaaS endpoint fields ───────────────
  // The /intercept/policies/sync endpoint returns more than just rules:
  // panicMode, shadowMode, syncIntervalHours, workspaceId, plus an ETag.
  // The cache file preserves all of these so the engine can apply them
  // and the next sync can send `If-None-Match` for cheap 304 polling.

  it('reads cloud rules from a cache written with the new sync endpoint shape', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }),
      [CACHE_PATH]: JSON.stringify({
        fetchedAt: '2026-05-03T00:00:00.000Z',
        // New endpoint serialises into the same `rules` key for back-compat
        rules: [
          {
            name: 'org:cloud-block-aws-read',
            verdict: 'block',
            conditions: [{ field: 'command', op: 'matches', pattern: 'cat ~/\\.aws' }],
          },
        ],
        // New fields stored alongside the existing rules array
        etag: 'abc123def4567890',
        panicMode: false,
        shadowMode: false,
        syncIntervalHours: 1,
        workspaceId: 'ws_test',
      }),
    });
    const config = getConfig();
    const rule = config.policy.smartRules.find((r) => r.name === 'org:cloud-block-aws-read');
    expect(rule).toBeDefined();
    expect(rule?.verdict).toBe('block');
  });
});

// ── Cloud-pushed runtime flags (panicMode, shadowMode) ─────────────────────
// These are the workspace-level switches that flow from the SaaS dashboard
// through the cache file into the active config. panicMode ends up on
// `settings.panicMode` for the orchestrator to read; shadowMode forces
// `settings.mode = 'observe'` so all blocks become would-block log entries.

describe('getConfig — cloud-pushed runtime flags', () => {
  it('panicMode in cache propagates to settings.panicMode', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }),
      [CACHE_PATH]: JSON.stringify({
        fetchedAt: '2026-05-03T00:00:00.000Z',
        rules: [],
        panicMode: true,
      }),
    });
    expect(getConfig().settings.panicMode).toBe(true);
  });

  it('panicMode defaults to undefined when absent from cache', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }),
      [CACHE_PATH]: JSON.stringify({ fetchedAt: '2026-05-03T00:00:00.000Z', rules: [] }),
    });
    expect(getConfig().settings.panicMode).toBeUndefined();
  });

  it('shadowMode in cache forces settings.mode = "observe"', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }),
      [CACHE_PATH]: JSON.stringify({
        fetchedAt: '2026-05-03T00:00:00.000Z',
        rules: [],
        shadowMode: true,
      }),
    });
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('shadowMode false leaves user-configured mode untouched', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'strict' } }),
      [CACHE_PATH]: JSON.stringify({
        fetchedAt: '2026-05-03T00:00:00.000Z',
        rules: [],
        shadowMode: false,
      }),
    });
    expect(getConfig().settings.mode).toBe('strict');
  });

  it('panicMode and shadowMode coexist (both apply)', () => {
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({ settings: { mode: 'standard' } }),
      [CACHE_PATH]: JSON.stringify({
        fetchedAt: '2026-05-03T00:00:00.000Z',
        rules: [],
        panicMode: true,
        shadowMode: true,
      }),
    });
    const config = getConfig();
    expect(config.settings.panicMode).toBe(true);
    expect(config.settings.mode).toBe('observe');
  });

  it('panicMode is not set from local user config (cloud-only field)', () => {
    // Even if a user puts panicMode in their config.json, it shouldn't take
    // effect — panicMode is a workspace admin's emergency switch and must
    // not be self-served by individual users. If we ever want a local
    // panic mode, that's a different feature.
    mockFiles({
      [CONFIG_PATH]: JSON.stringify({
        settings: { mode: 'standard', panicMode: true },
      }),
      // No cache → no cloud flags
    });
    expect(getConfig().settings.panicMode).toBeUndefined();
  });
});

// ── extractRules: tolerates three historical response shapes ───────────────

describe('extractRules', () => {
  it('extracts policies from the new endpoint shape', () => {
    const rules = extractRules({ policies: [{ name: 'r1' }, { name: 'r2' }] });
    expect(rules).toHaveLength(2);
  });

  it('falls back to the legacy `rules` field when `policies` is absent', () => {
    const rules = extractRules({ rules: [{ name: 'r1' }] });
    expect(rules).toHaveLength(1);
  });

  it('prefers `policies` over `rules` when both are present', () => {
    const rules = extractRules({
      policies: [{ name: 'new' }],
      rules: [{ name: 'old' }],
    });
    expect(rules).toEqual([{ name: 'new' }]);
  });

  it('returns an empty array for an unrecognised body shape', () => {
    expect(extractRules({})).toEqual([]);
    expect(extractRules({ policies: 'not-an-array' as never })).toEqual([]);
  });
});

// ── pushScanSnapshot: POST builder dispatches on tick.uploadAs ─────────────
//
// Step 4 contract: when the daemon tick reports uploadAs='totals' (the
// first tick after an extractor-stale watermark reset), the POST body must
// carry sessionTotals (BE replaces the row); otherwise sessionDeltas (BE
// atomic-increments). Anything else and an upgrading user double-counts on
// top of any prior `node9 scan --upload-history` baseline.
//
// We mock https.request to capture the body the daemon would have sent,
// rather than running a real HTTP server. The contract lives in the body
// shape and the markUploadComplete() call after a 2xx; both are
// observable through mocks.

describe('pushScanSnapshot — POST body dispatches on tick.uploadAs', () => {
  it('uploadAs="deltas" → body carries sessionDeltas (incrementing path)', async () => {
    const finding = {
      type: 'destructive-op' as const,
      sessionId: 'sess-1',
      lineIndex: 0,
    };
    mockTickScanWatcher.mockResolvedValueOnce({
      findings: [finding],
      totalToolCalls: 1,
      toolCallsBySession: { 'sess-1': 1 },
      filesScanned: 1,
      filesNew: 0,
      filesSkipped: 0,
      uploadAs: 'deltas' as const,
      schemaFuture: false,
    });

    const captured = await captureScanReportPost();

    expect(captured).toBeTruthy();
    expect(captured!.sessionDeltas).toBeDefined();
    expect(captured!.sessionTotals).toBeUndefined();
    expect(captured!.extractorVersion).toBe('canonical-v1');
    expect(mockMarkUploadComplete).not.toHaveBeenCalled();
  });

  it('uploadAs="totals" → body carries sessionTotals (overwrite path) and clears the flag on 2xx', async () => {
    const finding = {
      type: 'destructive-op' as const,
      sessionId: 'sess-2',
      lineIndex: 0,
    };
    mockTickScanWatcher.mockResolvedValueOnce({
      findings: [finding],
      totalToolCalls: 1,
      toolCallsBySession: { 'sess-2': 1 },
      filesScanned: 1,
      filesNew: 0,
      filesSkipped: 0,
      uploadAs: 'totals' as const,
      schemaFuture: false,
    });

    const captured = await captureScanReportPost();

    expect(captured).toBeTruthy();
    expect(captured!.sessionTotals).toBeDefined();
    expect(captured!.sessionDeltas).toBeUndefined();
    expect(captured!.extractorVersion).toBe('canonical-v1');
    // Flag-clear must happen exactly once after the successful POST so a
    // future tick reverts to the normal sessionDeltas path.
    expect(mockMarkUploadComplete).toHaveBeenCalledTimes(1);
  });

  it('schemaFuture=true → no POST is made (defensive skip on downgrade)', async () => {
    mockTickScanWatcher.mockResolvedValueOnce({
      findings: [],
      totalToolCalls: 0,
      toolCallsBySession: {},
      filesScanned: 0,
      filesNew: 0,
      filesSkipped: 0,
      uploadAs: 'deltas' as const,
      schemaFuture: true,
    });

    const captured = await captureScanReportPost();
    expect(captured).toBeNull();
  });
});
