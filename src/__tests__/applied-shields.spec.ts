// N6 — policy.appliedShields: the apply loop's own testimony of which
// shields it actually injected (doc/n6-state-aware-scan.md §1).
//
// Renderers (scan/posture) read this field to phrase recommendations, so
// its contract is load-bearing: a shield listed here IS enforcing; a
// shield absent is NOT — including a cloud-mandated name whose body
// failed to resolve (fail-closed, B1 #2), which the raw local∪cloud
// union would misreport as running.
//
// Harness cloned from b1-cloud-shield-unweakenable.spec.ts: real
// getConfig + real catalog; only the local-file readers are mocked
// (their path is a module-load-time const HOME can't move).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const activeShields = { current: [] as string[] };

vi.mock('../shields', async () => {
  const actual = await vi.importActual<typeof import('../shields')>('../shields');
  return {
    ...actual,
    readActiveShields: () => activeShields.current,
    readShieldOverrides: () => ({}),
  };
});

import { getConfig, _resetConfigCache } from '../config';

describe('N6 — policy.appliedShields is the apply loop testimony', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  const setCloud = (cloudShields: string[]) => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-07-01T00:00:00Z',
        rules: [],
        shields: cloudShields,
      })
    );
    _resetConfigCache();
  };

  const setLocal = (active: string[]) => {
    activeShields.current = active;
    _resetConfigCache();
  };

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-n6-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    activeShields.current = [];
    _resetConfigCache();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    _resetConfigCache();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('nothing enabled → empty ARRAY, never undefined (a renderer must not read absence as unknown)', () => {
    expect(getConfig().policy.appliedShields).toEqual([]);
  });

  it('locally enabled shields are listed, sorted', () => {
    setLocal(['redis', 'bash-safe']);
    expect(getConfig().policy.appliedShields).toEqual(['bash-safe', 'redis']);
  });

  it('a cloud-mandated shield is listed', () => {
    setCloud(['postgres']);
    expect(getConfig().policy.appliedShields).toEqual(['postgres']);
  });

  it('a shield enabled both locally and by mandate appears ONCE', () => {
    setCloud(['redis']);
    setLocal(['redis']);
    expect(getConfig().policy.appliedShields).toEqual(['redis']);
  });

  it('a mandated name with no resolvable body is ABSENT — fail-closed mandates are not "running"', () => {
    // B1 #2: a cloud mandate resolves its body from BUILTIN_SHIELDS only;
    // an unknown name is dropped rather than enforced. Reporting it as
    // applied would let scan/posture claim coverage that does not exist.
    setCloud(['no-such-shield', 'redis']);
    expect(getConfig().policy.appliedShields).toEqual(['redis']);
  });

  it('testimony matches injection: every listed shield contributed at least one smartRule', () => {
    setLocal(['redis', 'project-jail']);
    const cfg = getConfig();
    const names = cfg.policy.smartRules.map((r) => r.name ?? '');
    for (const shield of cfg.policy.appliedShields ?? []) {
      expect(names.some((n) => n.startsWith(`shield:${shield}:`))).toBe(true);
    }
  });
});
