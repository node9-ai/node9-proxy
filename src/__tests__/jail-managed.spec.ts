// src/__tests__/jail-managed.spec.ts
// Managed credential-jail paths → synthesized org:-prefixed smartRules, and the
// gate-not-cage guarantee (a managed block jail rule actually blocks the read).
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';
import { evaluatePolicy } from '../core.js';

describe('managed jailPaths apply', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-jail-mgd-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-07-01T00:00:00Z',
        rules: [],
        managedConfig: {
          jailPaths: [{ path: '~/.secrets', verdict: 'block' }],
          locked: [],
        },
      })
    );
    _resetConfigCache();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
  });

  it('injects org:-prefixed path rules from managed jailPaths', () => {
    const jail = getConfig().policy.smartRules.filter(
      (r) => r.name?.startsWith('org:') && r.name.includes('-path-')
    );
    expect(jail.length).toBe(2); // -bash + -anytool
    expect(jail.every((r) => r.verdict === 'block')).toBe(true);
    expect(jail.some((r) => r.name?.endsWith('-bash'))).toBe(true);
  });

  it('a managed block jail rule blocks a read of that path (gate)', async () => {
    const r = await evaluatePolicy('Bash', { command: 'cat ~/.secrets' });
    expect(r.decision).toBe('block');
  });
});
