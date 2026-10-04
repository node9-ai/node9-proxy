// The one config writer and the one-time migration, at the unit level: a
// file keeps its format, a missing file is created legacy, writes under the
// lock never lose each other, migration writes only departures from the
// defaults with a backup, is idempotent, undoes byte for byte, and leaves a
// file it cannot read alone.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { DEFAULT_CONFIG, RUNTIME_ONLY_CONFIG_KEYS, _resetConfigCache } from '../config';
import {
  writeLocalConfig,
  writeLocalSetting,
  readConfigFileView,
  globalConfigPath,
} from '../config/write';
import { migrateConfigFile, undoMigration, autoMigrateLocalConfig } from '../config/migrate';
import { isV2File } from '../config/v2';

let tmpHome: string;
let origHome: string | undefined;
let origUserprofile: string | undefined;

beforeAll(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-migrate-'));
  origHome = process.env.HOME;
  origUserprofile = process.env.USERPROFILE;
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
});

afterAll(() => {
  process.env.HOME = origHome;
  process.env.USERPROFILE = origUserprofile;
  _resetConfigCache();
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

const file = () => globalConfigPath();
const read = () => JSON.parse(fs.readFileSync(file(), 'utf8')) as Record<string, unknown>;
const initWroteDefaults = () => {
  const f = JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as Record<string, unknown>;
  for (const k of RUNTIME_ONLY_CONFIG_KEYS) delete f[k];
  return f;
};

beforeEach(() => {
  for (const f of fs.readdirSync(path.join(tmpHome, '.node9')))
    fs.rmSync(path.join(tmpHome, '.node9', f), { force: true });
  _resetConfigCache();
});

describe('writeConfigFile', () => {
  it('a missing file is created in the legacy shape', () => {
    writeLocalSetting('autoStartDaemon', false);
    const data = read();
    expect(isV2File(data)).toBe(false);
    expect((data.settings as Record<string, unknown>).autoStartDaemon).toBe(false);
  });

  it('a legacy file stays legacy, with its other keys intact', () => {
    fs.writeFileSync(
      file(),
      JSON.stringify({ version: '1.0', custom: 42, settings: { mode: 'strict' } })
    );
    writeLocalSetting('autoStartDaemon', false);
    const data = read();
    expect(data.custom).toBe(42);
    expect(data.settings).toEqual({ mode: 'strict', autoStartDaemon: false });
  });

  it('a v2 file stays v2 and the mutation lands in its v2 home', () => {
    fs.writeFileSync(file(), JSON.stringify({ version: '2', checks: { 'commands.sudo': 'off' } }));
    writeLocalConfig((f) => {
      f.policy = {
        ...(f.policy ?? {}),
        egress: { enabled: true, mode: 'block', allow: ['*.corp.com'] },
      };
    });
    const data = read();
    expect(isV2File(data)).toBe(true);
    expect(data.checks).toEqual({ 'commands.sudo': 'off', 'network.unknown-host': 'block' });
    expect(data.tuning).toEqual({ 'network.unknown-host': { allow: ['*.corp.com'] } });
    expect(readConfigFileView(file()).legacy.policy?.egress).toMatchObject({
      enabled: true,
      mode: 'block',
    });
  });

  it('refuses to overwrite a file it cannot read', () => {
    fs.writeFileSync(file(), '{broken');
    expect(() => writeLocalSetting('autoStartDaemon', false)).toThrow(/not valid JSON/);
    expect(fs.readFileSync(file(), 'utf8')).toBe('{broken');
  });

  it('two writers in a row both land (no lost update)', () => {
    writeLocalSetting('a', 1);
    writeLocalSetting('b', 2);
    expect(read().settings).toEqual({ a: 1, b: 2 });
    expect(fs.existsSync(file() + '.lock')).toBe(false);
  });

  it('a stale lock from a dead process is taken over', () => {
    const lock = file() + '.lock';
    fs.writeFileSync(lock, '');
    const old = new Date(Date.now() - 60_000);
    fs.utimesSync(lock, old, old);
    writeLocalSetting('a', 1);
    expect(read().settings).toEqual({ a: 1 });
    expect(fs.existsSync(lock)).toBe(false);
  });

  it('a live lock makes the writer wait, then fail loudly', () => {
    fs.writeFileSync(file() + '.lock', '');
    const t0 = Date.now();
    expect(() => writeLocalSetting('a', 1)).toThrow(/locked by another node9 process/);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(1500);
    fs.rmSync(file() + '.lock');
  });
});

describe('migrateConfigFile', () => {
  it('a file node9 init wrote becomes { version: "2" } with a backup, and the backup is the old bytes', () => {
    const before = JSON.stringify(initWroteDefaults(), null, 2);
    fs.writeFileSync(file(), before);
    const r = migrateConfigFile();
    expect(r.status).toBe('migrated');
    if (r.status !== 'migrated') return;
    expect(read()).toEqual({ version: '2' });
    expect(fs.readFileSync(r.backup, 'utf8')).toBe(before);
  });

  it('keeps departures from the defaults, drops the shipped rules the file carried', () => {
    const f = initWroteDefaults();
    (f.settings as Record<string, unknown>).mode = 'strict';
    (f.policy as Record<string, unknown>).commandChecks = { inlineExec: 'off' };
    ((f.policy as Record<string, unknown>).smartRules as unknown[]).push({
      name: 'mine',
      tool: 'bash',
      conditions: [{ field: 'command', op: 'contains', value: 'x' }],
      verdict: 'review',
    });
    fs.writeFileSync(file(), JSON.stringify(f));
    expect(migrateConfigFile().status).toBe('migrated');
    const data = read();
    expect(data.mode).toBe('strict');
    expect(data.checks).toEqual({ 'commands.inline-exec': 'off' });
    expect((data.rules as unknown[]).map((r) => (r as { name: string }).name)).toEqual(['mine']);
  });

  it('is idempotent and dry-run changes nothing', () => {
    fs.writeFileSync(file(), JSON.stringify({ settings: { mode: 'strict' } }));
    const dry = migrateConfigFile({ dryRun: true });
    expect(dry.status).toBe('dry-run');
    expect(fs.readFileSync(file(), 'utf8')).toBe(JSON.stringify({ settings: { mode: 'strict' } }));
    expect(migrateConfigFile().status).toBe('migrated');
    expect(migrateConfigFile().status).toBe('already-v2');
    expect(
      fs.readdirSync(path.join(tmpHome, '.node9')).filter((n) => n.includes('.bak-'))
    ).toHaveLength(1);
  });

  it('no file: nothing to do; a broken file: left alone and reported', () => {
    expect(migrateConfigFile().status).toBe('no-file');
    fs.writeFileSync(file(), '{broken');
    const r = migrateConfigFile();
    expect(r.status).toBe('failed');
    expect(fs.readFileSync(file(), 'utf8')).toBe('{broken');
  });

  it('a second migration after the first finds v2 under the lock: one backup only', () => {
    fs.writeFileSync(file(), JSON.stringify({ settings: { mode: 'strict' } }));
    expect(migrateConfigFile().status).toBe('migrated');
    expect(migrateConfigFile().status).toBe('already-v2');
    const backups = fs.readdirSync(path.join(tmpHome, '.node9')).filter((n) => n.includes('.bak-'));
    expect(backups).toHaveLength(1);
  });

  it('undo puts the newest backup back byte for byte and removes it', () => {
    const before = JSON.stringify({ settings: { mode: 'strict' }, custom: 1 });
    fs.writeFileSync(file(), before);
    expect(migrateConfigFile().status).toBe('migrated');
    expect(undoMigration()).not.toBeNull();
    expect(fs.readFileSync(file(), 'utf8')).toBe(before);
    expect(undoMigration()).toBeNull();
  });

  it('autoMigrateLocalConfig honours NODE9_NO_CONFIG_MIGRATE, stays off under tests, never throws', () => {
    fs.writeFileSync(file(), JSON.stringify({ settings: { mode: 'strict' } }));
    // NODE9_TESTING=1 alone: off, so a stray spawn cannot touch a real HOME.
    expect(autoMigrateLocalConfig()).toBeNull();
    process.env.NODE9_TEST_CONFIG_MIGRATE = '1';
    try {
      process.env.NODE9_NO_CONFIG_MIGRATE = '1';
      expect(autoMigrateLocalConfig()).toBeNull();
      delete process.env.NODE9_NO_CONFIG_MIGRATE;
      expect(isV2File(read())).toBe(false);
      fs.writeFileSync(file(), '{broken');
      expect(autoMigrateLocalConfig()?.status).toBe('failed');
    } finally {
      delete process.env.NODE9_TEST_CONFIG_MIGRATE;
    }
  });

  it('the migrated file resolves to the same checks as the legacy one', async () => {
    const f = initWroteDefaults();
    (f.policy as Record<string, unknown>).commandChecks = { inlineExec: 'off', chmod: 'block' };
    (f.policy as Record<string, unknown>).dlp = {
      enabled: true,
      scanIgnoredTools: true,
      pii: 'off',
    };
    fs.writeFileSync(file(), JSON.stringify(f));
    const { getConfig } = await import('../config/index.js');
    const before = getConfig().policy.checks;
    expect(migrateConfigFile().status).toBe('migrated');
    _resetConfigCache();
    const after = getConfig().policy.checks;
    expect(after).toEqual(before);
  });
});
