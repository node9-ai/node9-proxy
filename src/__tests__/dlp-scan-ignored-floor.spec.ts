// src/__tests__/dlp-scan-ignored-floor.spec.ts
//
// Task #23 — a local `dlp.scanIgnoredTools:false` must not defeat an ORG DLP
// mandate.
//
// applyManagedDlp floors `enabled` (force-on), `pii` and `reviewAction` (by
// strictness order) — but had no `scanIgnoredTools` handling, and the SaaS
// ResolvedManagedConfig.dlp only carries {enabled,pii,reviewAction}, so an org
// could not enforce it from either side. A device that set it false silently
// turned DLP off for the whole ignoredTools class (read/grep/glob/ls) while the
// dashboard still showed DLP mandated.
//
// Found by the DLP gauntlet (task #19): Grep with a secret as the pattern is
// blocked by default and was ALLOWED with the local carve-out. Same family as
// task #16 vector B — a local carve-out defeating an org mandate.
//
// SCOPE (measured, not assumed): path-based sensitive reads such as
// `Read ~/.ssh/id_rsa` stay blocked by the project-jail shield
// (shield:project-jail:block-read-ssh-any-tool), so this was secret-in-args
// exposure for ignored tools, not a total DLP bypass.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';

/** Composed so this file never trips DLP itself (repo convention). */
const FAKE_AWS_KEY = 'AKIA' + 'J2XZKZMV' + 'P3NQRSTU';

/** The org turns DLP on. It cannot express scanIgnoredTools at all. */
const ORG_DLP_ON = {
  fetchedAt: '2026-07-01T00:00:00Z',
  rules: [],
  managedConfig: { dlp: { enabled: true, reviewAction: 'block' } },
};

const APPROVERS_OFF = { native: false, browser: false, cloud: false, terminal: false };
const BASE_SETTINGS = { mode: 'standard', approvalTimeoutMs: 0, approvers: APPROVERS_OFF };

describe('an org DLP mandate survives a local scanIgnoredTools carve-out (task #23)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-dlp-floor-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    _resetConfigCache();
    _resetCore();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
    _resetCore();
  });

  function seed(policy: object, cache: object = ORG_DLP_ON): void {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: BASE_SETTINGS, policy })
    );
    fs.writeFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), JSON.stringify(cache));
    _resetConfigCache();
    _resetCore();
  }

  /** Grep is an ignoredTool; the secret rides in `pattern` — the real shape of
   *  a secret leaking through a "safe" tool's arguments. */
  const grepTheSecret = () =>
    authorizeHeadless('Grep', { pattern: FAKE_AWS_KEY }, { agent: 'MCP' }, {});

  it('CONTROL: with defaults, an ignored tool carrying a secret is blocked', async () => {
    seed({});
    const r = await grepTheSecret();
    expect(r.approved).toBe(false);
  });

  it('a local scanIgnoredTools:false does NOT disable the org mandate', async () => {
    seed({ dlp: { scanIgnoredTools: false } });
    const r = await grepTheSecret();
    expect(r.approved).toBe(false);
  });

  it('the resolved config keeps scanIgnoredTools on under the mandate', () => {
    seed({ dlp: { scanIgnoredTools: false } });
    expect(getConfig().policy.dlp.scanIgnoredTools).toBe(true);
  });

  it('the sibling carve-outs stay floored too (enabled, reviewAction)', async () => {
    seed({ dlp: { enabled: false, reviewAction: 'review', scanIgnoredTools: false } });
    const cfg = getConfig();
    expect(cfg.policy.dlp.enabled).toBe(true);
    expect(cfg.policy.dlp.scanIgnoredTools).toBe(true);
    const r = await grepTheSecret();
    expect(r.approved).toBe(false);
  });

  // ── Over-tightening guards ────────────────────────────────────────────────
  it('with NO org mandate, a local scanIgnoredTools:false is the dev own choice', async () => {
    // Unmanaged device: the config-home law leaves local posture alone.
    seed({ dlp: { scanIgnoredTools: false } }, { fetchedAt: '2026-07-01T00:00:00Z', rules: [] });
    expect(getConfig().policy.dlp.scanIgnoredTools).toBe(false);
    const r = await grepTheSecret();
    expect(r.approved).toBe(true);
  });

  it('an org mandate that turns DLP OFF does not force the scan on', () => {
    seed(
      { dlp: { scanIgnoredTools: false } },
      {
        fetchedAt: '2026-07-01T00:00:00Z',
        rules: [],
        managedConfig: { dlp: { enabled: false } },
      }
    );
    expect(getConfig().policy.dlp.scanIgnoredTools).toBe(false);
  });

  it('a clean call on an ignored tool is still allowed (not blanket-denying)', async () => {
    seed({ dlp: { scanIgnoredTools: false } });
    const r = await authorizeHeadless('Grep', { pattern: 'TODO' }, { agent: 'MCP' }, {});
    expect(r.approved).toBe(true);
  });
});
