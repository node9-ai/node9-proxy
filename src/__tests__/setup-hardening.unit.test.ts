import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { mayChangeService, SetupError } from '../cli/interactive';
import { getConfig, _resetConfigCache } from '../config';

describe('runtime-only config fields are never read from the file', () => {
  const homes: string[] = [];
  afterEach(() => {
    vi.restoreAllMocks();
    _resetConfigCache();
    for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
  });
  it('a file claiming workspace policy does not make a local machine managed', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-runtime-keys-'));
    homes.push(home);
    fs.mkdirSync(path.join(home, '.node9'));
    fs.writeFileSync(
      path.join(home, '.node9/config.json'),
      JSON.stringify({ policySource: 'workspace', ssrfStrictSource: 'workspace' })
    );
    vi.spyOn(os, 'homedir').mockReturnValue(home);
    _resetConfigCache();
    const config = getConfig(path.join(home, '.node9'));
    expect(config.policySource).toBe('local');
    expect(config.ssrfStrictSource).not.toBe('workspace');
  });
});

describe('login service needs a person at a real terminal', () => {
  it('a terminal outside CI may install it, including init --recommended', () => {
    expect(mayChangeService({ stdoutTTY: true, ci: false })).toBe(true);
  });
  it('CI never touches it, even with a terminal attached', () => {
    expect(mayChangeService({ stdoutTTY: true, ci: true })).toBe(false);
  });
  it('a pipe, a Docker build or an agent never touches it', () => {
    expect(mayChangeService({ stdoutTTY: false, ci: false })).toBe(false);
  });
  it('--skip-setup never touches it', () => {
    expect(mayChangeService({ stdoutTTY: true, ci: false, skipSetup: true })).toBe(false);
  });
});

describe('SetupError', () => {
  it('is an Error the setup commands can tell apart from a crash', () => {
    const e = new SetupError('fix this');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('SetupError');
    expect(e.message).toBe('fix this');
  });
});
