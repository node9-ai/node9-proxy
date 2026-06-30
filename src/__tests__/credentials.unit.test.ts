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
