import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { writeCredentialsAndConfig } from '../credentials';

describe('writeCredentialsAndConfig', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-creds-'));
  });
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const creds = () =>
    JSON.parse(fs.readFileSync(path.join(tmp, '.node9', 'credentials.json'), 'utf-8'));
  const config = () =>
    JSON.parse(fs.readFileSync(path.join(tmp, '.node9', 'config.json'), 'utf-8'));

  it('writes the default profile key + an approvers config (cloud on)', () => {
    const r = writeCredentialsAndConfig('n9_live_abc', { homeDir: tmp });
    expect(r).toEqual({ profileName: 'default', effectiveCloud: true });
    expect(creds().default.apiKey).toBe('n9_live_abc');
    expect(config().settings.approvers.cloud).toBe(true);
  });

  it('--local (isLocal) turns cloud approvals off', () => {
    const r = writeCredentialsAndConfig('n9_live_abc', { isLocal: true, homeDir: tmp });
    expect(r.effectiveCloud).toBe(false);
    expect(config().settings.approvers.cloud).toBe(false);
  });

  it('always sets cloud=true over an existing cloud:false (init-then-login trap)', () => {
    // `node9 init` seeds DEFAULT_CONFIG (cloud:false). Login MUST override it —
    // preserve-on-login is what used to lock machines out of the cloud forever.
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvers: { native: true, browser: false, cloud: false, terminal: true },
        },
      })
    );
    const r = writeCredentialsAndConfig('n9_live_abc', { homeDir: tmp });
    expect(r.effectiveCloud).toBe(true);
    expect(config().settings.approvers.cloud).toBe(true);
    expect(config().settings.mode).toBe('standard');
  });

  it('re-login without --local re-enables cloud after a --local login', () => {
    writeCredentialsAndConfig('n9_live_abc', { isLocal: true, homeDir: tmp });
    const r = writeCredentialsAndConfig('n9_live_abc', { homeDir: tmp });
    expect(r.effectiveCloud).toBe(true);
    expect(config().settings.approvers.cloud).toBe(true);
  });

  it('preserves user-customized native/terminal approvers', () => {
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, '.node9', 'config.json'),
      JSON.stringify({ settings: { approvers: { native: false, terminal: false, cloud: false } } })
    );
    writeCredentialsAndConfig('n9_live_abc', { homeDir: tmp });
    expect(config().settings.approvers.native).toBe(false);
    expect(config().settings.approvers.terminal).toBe(false);
    expect(config().settings.approvers.cloud).toBe(true);
  });

  it('drops the legacy browser approver key on every write', () => {
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, '.node9', 'config.json'),
      JSON.stringify({ settings: { approvers: { native: true, browser: true, cloud: true } } })
    );
    writeCredentialsAndConfig('n9_live_abc', { homeDir: tmp });
    expect('browser' in config().settings.approvers).toBe(false);
    // Fresh configs never get the key either.
    const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-creds2-'));
    try {
      writeCredentialsAndConfig('n9_live_abc', { homeDir: tmp2 });
      const fresh = JSON.parse(fs.readFileSync(path.join(tmp2, '.node9', 'config.json'), 'utf-8'));
      expect('browser' in fresh.settings.approvers).toBe(false);
    } finally {
      fs.rmSync(tmp2, { recursive: true, force: true });
    }
  });

  it('a named profile writes creds but not the default config.json', () => {
    const r = writeCredentialsAndConfig('n9_live_x', { profileName: 'work', homeDir: tmp });
    expect(r).toEqual({ profileName: 'work', effectiveCloud: null });
    expect(creds().work.apiKey).toBe('n9_live_x');
    expect(fs.existsSync(path.join(tmp, '.node9', 'config.json'))).toBe(false);
  });

  it('merges a new profile alongside an existing one', () => {
    writeCredentialsAndConfig('k1', { homeDir: tmp });
    writeCredentialsAndConfig('k2', { profileName: 'work', homeDir: tmp });
    const c = creds();
    expect(c.default.apiKey).toBe('k1');
    expect(c.work.apiKey).toBe('k2');
  });

  it('migrates the legacy single-key shape into the profile map', () => {
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, '.node9', 'credentials.json'),
      JSON.stringify({ apiKey: 'old', apiUrl: 'u' })
    );
    writeCredentialsAndConfig('new', { profileName: 'work', homeDir: tmp });
    const c = creds();
    expect(c.default.apiKey).toBe('old');
    expect(c.work.apiKey).toBe('new');
  });
});
