// Unit + integration tests for `node9 egress` — the posture remediation on-ramp.
// Unit: applyEgress read-merge-write semantics. Integration: the real CLI
// subprocess writes ~/.node9/config.json (requires `npm run build`).

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { applyEgress } from '../cli/commands/egress';
import { isValidEgressHost, normalizeEgressHost } from '../auth/egress-config';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

describe('egress host validation (shared by CLI + MCP)', () => {
  it('accepts FQDNs and wildcard globs', () => {
    for (const h of ['app.node9.ai', 'node9.ai', '*.node9.ai', 'api.mycorp.co.uk']) {
      expect(isValidEgressHost(h), h).toBe(true);
    }
  });

  it('rejects non-hosts (spaces, schemes, bare words, empty)', () => {
    for (const h of ['not a host', 'http://node9.ai', 'localhost', 'node9', '']) {
      expect(isValidEgressHost(h), h).toBe(false);
    }
  });

  it('normalizes case and surrounding whitespace', () => {
    expect(normalizeEgressHost('  APP.Node9.AI  ')).toBe('app.node9.ai');
  });
});

describe('applyEgress (read-merge-write)', () => {
  it('sets the egress block without clobbering other config', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const config: any = {
      policy: { smartRules: ['keepme'], dlp: { enabled: true } },
      settings: { mode: 'standard' },
    };
    applyEgress(config, { enabled: true, mode: 'block' });
    expect(config.policy.egress).toEqual({
      enabled: true,
      mode: 'block',
      allow: [],
      deny: [],
      allowPrivate: true,
    });
    expect(config.policy.smartRules).toEqual(['keepme']); // untouched
    expect(config.settings.mode).toBe('standard'); // untouched
  });

  it('merges onto an existing egress block, preserving the allowlist', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const config: any = { policy: { egress: { enabled: true, mode: 'review', allow: ['x.com'] } } };
    applyEgress(config, { mode: 'block' });
    expect(config.policy.egress).toMatchObject({ enabled: true, mode: 'block', allow: ['x.com'] });
  });
});

describe('node9 egress (integration)', () => {
  let home: string;

  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI not found at ${CLI} — run npm run build`).toBe(true);
  });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-int-'));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  function run(args: string[]) {
    const baseEnv = { ...process.env };
    delete baseEnv.NODE9_API_KEY;
    return spawnSync(process.execPath, [CLI, 'egress', ...args], {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: os.tmpdir(),
      env: {
        ...baseEnv,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
        HOME: home,
        USERPROFILE: home,
      },
    });
  }
  const readEgress = () =>
    JSON.parse(fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf8')).policy.egress;

  it('watch → enabled review config on disk', () => {
    const r = run(['watch']);
    expect(r.status).toBe(0);
    expect(readEgress()).toMatchObject({ enabled: true, mode: 'review' });
  });

  it('lock → enabled block config', () => {
    run(['watch']);
    run(['lock']);
    expect(readEgress()).toMatchObject({ enabled: true, mode: 'block' });
  });

  it('allow → adds a host to the allowlist', () => {
    run(['watch']);
    run(['allow', '*.mycorp.com']);
    expect(readEgress().allow).toContain('*.mycorp.com');
  });

  it('off → disables', () => {
    run(['lock']);
    run(['off']);
    expect(readEgress().enabled).toBe(false);
  });

  it('status (no subcommand) prints and exits 0', () => {
    const r = run([]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Egress control/i);
  });

  it('refuses to overwrite a malformed config (exit 1, file untouched)', () => {
    const cfgPath = path.join(home, '.node9', 'config.json');
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    const broken = '{ "policy": { not valid json';
    fs.writeFileSync(cfgPath, broken);
    const r = run(['lock']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not valid JSON/i);
    // The user's (broken) config must be left exactly as-is, not clobbered.
    expect(fs.readFileSync(cfgPath, 'utf8')).toBe(broken);
  });
});
