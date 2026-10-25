// src/__tests__/levels-config.spec.ts
//
// The protection levels at load time (node9Firewall#385 item 5). A level is a
// set of defaults: getConfig gives every check nobody stated the level's
// value, both in the resolved checks map and in the legacy knob its gate
// still reads. A value a person, the workspace or the org stated wins; a
// project file may raise a level's value, never lower it.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';

describe('protection levels in getConfig', () => {
  let tmpHome: string;
  let projectDir: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  const writeLocal = (cfg: object) =>
    fs.writeFileSync(path.join(tmpHome, '.node9', 'config.json'), JSON.stringify(cfg));
  const writeProject = (cfg: object) =>
    fs.writeFileSync(path.join(projectDir, 'node9.config.json'), JSON.stringify(cfg));
  const writeCache = (cache: object) =>
    fs.writeFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), JSON.stringify(cache));
  const keyed = () =>
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'credentials.json'),
      JSON.stringify({ default: { apiKey: 'n9_test_levels' } })
    );
  const load = () => {
    _resetConfigCache();
    return getConfig(projectDir);
  };

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-levels-'));
    projectDir = path.join(tmpHome, 'project');
    fs.mkdirSync(projectDir);
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_MODE;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    delete process.env.NODE9_MODE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
  });

  it('Standard is exactly the defaults of an install with no mode', () => {
    writeLocal({ settings: {} });
    const none = load();
    writeLocal({ settings: { mode: 'standard' } });
    const std = load();
    expect(std.policy.checks).toEqual(none.policy.checks);
    expect(std.policy.egress).toEqual(none.policy.egress);
    expect(std.policy.untrustedContent).toEqual(none.policy.untrustedContent);
    expect(std.policy.packageCheck).toEqual(none.policy.packageCheck);
  });

  it('Soft lowers the review checks to log and turns the registry signals off', () => {
    writeLocal({ settings: { mode: 'soft' } });
    const c = load();
    expect(c.policy.checks?.['commands.rm']).toBe('log');
    expect(c.policy.checks?.['files.system-dirs']).toBe('log');
    expect(c.policy.checks?.['commands.curl-pipe-shell']).toBe('block');
    expect(c.policy.checks?.['data.secrets']).toBe('block');
    expect(c.policy.checks?.['behavior.untrusted-content']).toBe('log');
    expect(c.policy.untrustedContent.afterExposure).toBe('log-only');
    expect(c.policy.packageCheck.newPackage).toBe('off');
    expect(c.policy.packageCheck.installScript).toBe('off');
  });

  it('Strict turns on the unknown-host, internal-address, injection and skill checks', () => {
    writeLocal({ settings: { mode: 'strict' } });
    const c = load();
    expect(c.policy.egress.enabled).toBe(true);
    expect(c.policy.egress.mode).toBe('review');
    expect(c.policy.egress.ssrfStrict).toBe(true);
    expect(c.policy.injectionScan.enabled).toBe(true);
    expect(c.policy.skillPinning.enabled).toBe(true);
    expect(c.policy.skillPinning.mode).toBe('block');
    expect(c.policy.dlp.reviewAction).toBe('block');
    expect(c.policy.checks?.['network.unknown-host']).toBe('review');
    expect(c.policy.checks?.['data.secrets-weak']).toBe('block');
    expect(c.policy.checks?.['commands.sql-ddl']).toBe('block');
    expect(c.policy.checks?.['commands.unknown']).toBe('off');
  });

  it('Block all has the values of Strict plus the catch-all', () => {
    writeLocal({ settings: { mode: 'block-all' } });
    const c = load();
    expect(c.policy.egress.ssrfStrict).toBe(true);
    expect(c.policy.checks?.['commands.unknown']).toBe('review');
  });

  it('a value the user stated in the global file wins over the level', () => {
    writeLocal({
      settings: { mode: 'strict' },
      policy: { egress: { enabled: false }, commandChecks: { sqlDdl: 'review' } },
    });
    const c = load();
    expect(c.policy.egress.enabled).toBe(false);
    expect(c.policy.checks?.['network.unknown-host']).toBe('off');
    expect(c.policy.checks?.['commands.sql-ddl']).toBe('review');
    // An unstated check still takes the level.
    expect(c.policy.egress.ssrfStrict).toBe(true);
  });

  it('a v2 file entry wins over the level', () => {
    writeLocal({
      version: '2',
      mode: 'soft',
      checks: { 'commands.rm': 'review', 'behavior.untrusted-content': 'review' },
    });
    const c = load();
    expect(c.policy.checks?.['commands.rm']).toBe('review');
    expect(c.policy.checks?.['behavior.untrusted-content']).toBe('review');
    expect(c.policy.untrustedContent.afterExposure).not.toBe('log-only');
  });

  it('a seeded dlp.enabled does not pin the weak-credential check', () => {
    writeLocal({ settings: { mode: 'strict' }, policy: { dlp: { enabled: true } } });
    expect(load().policy.dlp.reviewAction).toBe('block');
  });

  it('a project file cannot lower a level value', () => {
    writeLocal({ settings: { mode: 'strict' } });
    writeProject({ policy: { egress: { enabled: false }, injectionScan: { enabled: false } } });
    const c = load();
    expect(c.policy.egress.enabled).toBe(true);
    expect(c.policy.injectionScan.enabled).toBe(true);
  });

  it('a project file may raise a level value', () => {
    writeLocal({ settings: { mode: 'soft' } });
    writeProject({ version: '2', checks: { 'commands.rm': 'review' } });
    expect(load().policy.checks?.['commands.rm']).toBe('review');
  });

  it('a project file that raised a knob check keeps it under Soft', () => {
    writeLocal({ settings: { mode: 'soft' } });
    writeProject({ policy: { untrustedContent: { afterExposure: 'ask-every-time' } } });
    const c = load();
    expect(c.policy.untrustedContent.afterExposure).toBe('ask-every-time');
    expect(c.policy.checks?.['behavior.untrusted-content']).toBe('review');
  });

  it('NODE9_MODE picks a level', () => {
    writeLocal({ settings: {} });
    process.env.NODE9_MODE = 'soft';
    expect(load().settings.mode).toBe('soft');
    expect(load().policy.checks?.['commands.rm']).toBe('log');
  });

  it('a keyed machine takes the workspace level, and the workspace values win', () => {
    keyed();
    writeCache({
      config: { checks: { 'network.internal-addresses': 'off' } },
      managedConfig: { mode: 'strict', egress: { ssrfStrict: false }, locked: [] },
    });
    const c = load();
    expect(c.settings.mode).toBe('strict');
    expect(c.policy.egress.ssrfStrict).toBe(false);
    expect(c.policy.injectionScan.enabled).toBe(true);
  });

  it('a keyed machine takes soft and block-all from the workspace', () => {
    keyed();
    writeCache({ managedConfig: { mode: 'soft', locked: [] } });
    expect(load().settings.mode).toBe('soft');
    writeCache({ managedConfig: { mode: 'block-all', locked: [] } });
    expect(load().settings.mode).toBe('block-all');
  });

  it('an unkeyed machine floors its level to the managed one', () => {
    writeLocal({ settings: { mode: 'soft' } });
    writeCache({ managedConfig: { mode: 'strict', locked: [] } });
    expect(load().settings.mode).toBe('strict');
    writeLocal({ settings: { mode: 'block-all' } });
    expect(load().settings.mode).toBe('block-all');
  });
});
