// src/__tests__/skill-roots-config.spec.ts
// Unit tests for policy.skillPinning config field — enabled, mode, roots.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';

describe('policy.skillPinning config field', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-cfg-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
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

  it('defaults to enabled=false, mode=warn, roots=[]', () => {
    const sp = getConfig().policy.skillPinning;
    expect(sp.enabled).toBe(false);
    expect(sp.mode).toBe('warn');
    expect(sp.roots).toEqual([]);
  });

  it('merges user-supplied skillPinning from config.json', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        policy: {
          skillPinning: { enabled: true, mode: 'block', roots: ['~/my-skills'] },
        },
      })
    );
    const sp = getConfig().policy.skillPinning;
    expect(sp.enabled).toBe(true);
    expect(sp.mode).toBe('block');
    expect(sp.roots).toEqual(['~/my-skills']);
  });

  it('de-duplicates roots', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ policy: { skillPinning: { enabled: true, roots: ['~/a', '~/a', '~/b'] } } })
    );
    expect(getConfig().policy.skillPinning.roots).toEqual(['~/a', '~/b']);
  });

  it('partial config only overrides specified fields', () => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ policy: { skillPinning: { enabled: true } } })
    );
    const sp = getConfig().policy.skillPinning;
    expect(sp.enabled).toBe(true);
    expect(sp.mode).toBe('warn'); // default preserved
    expect(sp.roots).toEqual([]); // default preserved
  });
});
