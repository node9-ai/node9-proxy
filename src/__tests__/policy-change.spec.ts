// What a policy sync changed (node9-proxy#506): the lines, the record the
// daemon's sync leaves for the CLI, and the state line. The caches compared
// are built by the sync's own mapping (cacheFromSyncBody) from bodies shaped
// like the ones GET /policies/sync returns, and written by its own writer.
import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { __writeCacheForTest, cacheFromSyncBody, type CloudPolicyBody } from '../daemon/sync';
import {
  LAST_CHANGE_MAX_AGE_MS,
  policyChangeLines,
  policyChangePath,
  policyStateLine,
  readPolicyChange,
  recordPolicyChange,
} from '../daemon/policy-change';
import { _resetConfigCache } from '../config';

const cleanup: Array<() => void> = [];
afterEach(() => {
  for (const c of cleanup.splice(0)) c();
  vi.unstubAllEnvs();
  _resetConfigCache();
});

function home(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-policy-change-'));
  cleanup.push(() => fs.rmSync(h, { recursive: true, force: true }));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  vi.stubEnv('HOME', h);
  vi.stubEnv('USERPROFILE', h);
  return h;
}

/** A sync body as the server sends it for a workspace on Audit with the
 *  approved list on and nothing decided. */
function body(over: Partial<CloudPolicyBody> = {}): CloudPolicyBody {
  return {
    policies: [],
    panicMode: false,
    shadowMode: false,
    syncIntervalHours: 1,
    workspaceId: 'ws-1',
    shields: ['postgres'],
    managedConfig: {
      mode: 'observe',
      dlp: { enabled: true, pii: 'off' },
      addons: { unapproved: 'log', mcp: {}, skills: {}, plugins: {} },
      locked: ['mode'],
    },
    ...over,
  } as CloudPolicyBody;
}

const cache = (b: CloudPolicyBody) =>
  cacheFromSyncBody(b, 'etag') as unknown as Record<string, unknown>;

const managed = (over: Record<string, unknown>): CloudPolicyBody =>
  body({ managedConfig: { ...body().managedConfig, ...over } } as Partial<CloudPolicyBody>);

describe('policyChangeLines', () => {
  it('says nothing for a first sync, or for the same policy fetched again', () => {
    expect(policyChangeLines(null, cache(body()))).toEqual([]);
    // fetchedAt and the etag differ between two syncs; the policy does not.
    expect(policyChangeLines(cache(body()), cache(body()))).toEqual([]);
  });

  it('names a change of level in the words node9 status uses', () => {
    expect(policyChangeLines(cache(body()), cache(managed({ mode: 'standard' })))).toEqual([
      'Level: audit → standard',
    ]);
    // No managed mode at all is Standard.
    expect(
      policyChangeLines(cache(managed({ mode: 'strict' })), cache(managed({ mode: undefined })))
    ).toEqual(['Level: strict → standard']);
  });

  it('names an add-on blocked, approved and cleared, and the rule for the undecided ones', () => {
    const blocked = managed({
      addons: {
        unapproved: 'block',
        mcp: { 'url:gmailmcp.googleapis.com': 'blocked' },
        skills: { deploy: { decision: 'approved', hashes: ['a'.repeat(64)] } },
        plugins: {},
      },
    });
    const lines = policyChangeLines(cache(body()), cache(blocked));
    expect(lines).toContain('Add-ons nobody approved: allow and alert → block until approved');
    expect(lines).toContain('MCP server url:gmailmcp.googleapis.com: no decision → blocked');
    expect(lines).toContain('skill deploy: no decision → approved');
    // Cleared again on the dashboard.
    expect(policyChangeLines(cache(blocked), cache(body()))).toContain(
      'MCP server url:gmailmcp.googleapis.com: blocked → no decision'
    );
  });

  it('counts the decisions past the first six', () => {
    const mcp = Object.fromEntries(
      Array.from({ length: 9 }, (_, i) => [`npm:pkg-${i}`, 'blocked'])
    );
    const lines = policyChangeLines(
      cache(body()),
      cache(managed({ addons: { unapproved: 'log', mcp, skills: {}, plugins: {} } }))
    );
    expect(lines.filter((l) => l.startsWith('MCP server'))).toHaveLength(6);
    expect(lines).toContain('and 3 more add-on decisions');
  });

  it('names rule, shield and panic changes, and puts every other setting in one line', () => {
    const next = body({
      policies: [{ name: 'r1' }],
      shields: ['github'],
      panicMode: true,
      managedConfig: { ...body().managedConfig, dlp: { enabled: false, pii: 'off' } },
    } as Partial<CloudPolicyBody>);
    expect(policyChangeLines(cache(body()), cache(next))).toEqual([
      'Panic mode: off → on',
      'Custom rules: 0 → 1',
      'Shields added: github',
      'Shields removed: postgres',
      'Other settings changed',
    ]);
  });

  it('reads the spend budget level as a status, not as a setting somebody changed', () => {
    const budget = (level: number, month: string, limitUSD = 200) =>
      managed({ spendBudget: { month, level, limitUSD, coveredProviders: ['ANTHROPIC'] } });
    // The month rolls over and the level drops back: no setting changed.
    expect(policyChangeLines(cache(budget(0, '2026-11')), cache(budget(0, '2026-12')))).toEqual([]);
    expect(policyChangeLines(cache(budget(75, '2026-11')), cache(budget(90, '2026-11')))).toEqual([
      'Spend budget used: 75% → 90% of the limit',
    ]);
    // The limit itself is a setting.
    expect(
      policyChangeLines(cache(budget(0, '2026-11')), cache(budget(0, '2026-11', 500)))
    ).toEqual(['Other settings changed']);
  });

  it('keeps control characters from a decision name off the terminal', () => {
    const lines = policyChangeLines(
      cache(body()),
      cache(
        managed({
          addons: {
            unapproved: 'log',
            mcp: { 'npm:evil\u001b[2Jpkg': 'blocked' },
            skills: {},
            plugins: {},
          },
        })
      )
    );
    expect(lines.join('\n')).not.toMatch(/\u001b/);
  });

  it('never throws on a cache of another shape', () => {
    expect(() =>
      policyChangeLines({ managedConfig: 7, rules: 'x' }, { shields: {} })
    ).not.toThrow();
  });
});

describe('the record a sync leaves', () => {
  it('is written by the cache writer when the policy changed, and not when it did not', () => {
    const h = home();
    // A first sync: nothing to compare with.
    expect(__writeCacheForTest(cacheFromSyncBody(body(), 'e1'))).toEqual([]);
    expect(fs.existsSync(policyChangePath(h))).toBe(false);
    // The dashboard moved the workspace to Standard.
    expect(__writeCacheForTest(cacheFromSyncBody(managed({ mode: 'standard' }), 'e2'))).toEqual([
      'Level: audit → standard',
    ]);
    expect(readPolicyChange(h)?.lines).toEqual(['Level: audit → standard']);
    // The same policy again: the record still tells of the last change.
    expect(__writeCacheForTest(cacheFromSyncBody(managed({ mode: 'standard' }), 'e3'))).toEqual([]);
    expect(readPolicyChange(h)?.lines).toEqual(['Level: audit → standard']);
    // Only this user reads it.
    if (process.platform !== 'win32') expect(fs.statSync(policyChangePath(h)).mode & 0o077).toBe(0);
  });

  it('a change it cannot name does not replace a named one that is still shown', () => {
    const h = home();
    __writeCacheForTest(cacheFromSyncBody(body(), 'e1'));
    __writeCacheForTest(cacheFromSyncBody(managed({ mode: 'standard' }), 'e2'));
    // A setting with no line of its own changes in the next sync.
    const other = managed({ mode: 'standard', dlp: { enabled: false, pii: 'off' } });
    expect(__writeCacheForTest(cacheFromSyncBody(other, 'e3'))).toEqual(['Other settings changed']);
    expect(readPolicyChange(h)?.lines).toEqual(['Level: audit → standard']);
    // With nothing named on record, it is the last change.
    fs.rmSync(policyChangePath(h));
    __writeCacheForTest(cacheFromSyncBody(managed({ mode: 'standard' }), 'e4'));
    expect(readPolicyChange(h)?.lines).toEqual(['Other settings changed']);
  });

  it('is not shown once it is a day old, from the future, or not ours', () => {
    const h = home();
    const now = Date.parse('2026-11-28T12:00:00Z');
    recordPolicyChange(['Level: audit → standard'], h, now);
    expect(readPolicyChange(h, now + 60_000)?.at).toBe('2026-11-28T12:00:00.000Z');
    expect(readPolicyChange(h, now + LAST_CHANGE_MAX_AGE_MS + 1)).toBeNull();
    // A clock stepped back a little still shows it; an hour ahead is not ours.
    expect(readPolicyChange(h, now - 60_000)?.lines).toEqual(['Level: audit → standard']);
    expect(readPolicyChange(h, now - 3_600_000)).toBeNull();
    fs.writeFileSync(policyChangePath(h), '{"at":"yesterday","lines":["x"]}');
    expect(readPolicyChange(h, now)).toBeNull();
    fs.writeFileSync(policyChangePath(h), '{not json');
    expect(readPolicyChange(h, now)).toBeNull();
  });
});

describe('policyStateLine', () => {
  it('gives the level, the rule for undecided add-ons and how many are blocked', () => {
    expect(policyStateLine(cache(body()))).toBe(
      'Level: audit · add-ons nobody approved: allow and alert'
    );
    expect(
      policyStateLine(
        cache(
          managed({
            mode: 'standard',
            addons: {
              unapproved: 'block',
              mcp: { 'url:a.example': 'blocked', 'npm:b': 'approved' },
              skills: {},
              plugins: {},
            },
          })
        )
      )
    ).toBe('Level: standard · add-ons nobody approved: block until approved · 1 add-on blocked');
    expect(policyStateLine(null)).toBe('');
  });
});
