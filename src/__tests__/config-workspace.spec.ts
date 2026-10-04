// Phase 3a, the proxy half: a keyed machine takes the workspace's checks
// from the sync body's `config` block. Harness cloned from keyed-replace:
// credentials.json keys the machine, rules-cache.json is the cloud cache.
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../shields', async () => {
  const actual = await vi.importActual<typeof import('../shields')>('../shields');
  return { ...actual, readActiveShields: () => [], readShieldOverrides: () => ({}) };
});

import { getConfig, _resetConfigCache } from '../config';
import { extractWorkspaceConfig } from '../daemon/sync';
import { evaluatePolicy } from '../policy';
import { buildChecksReport } from '../cli/commands/checks';

let home: string;
let origHome: string | undefined;
let origUserprofile: string | undefined;

beforeAll(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-ws-'));
  origHome = process.env.HOME;
  origUserprofile = process.env.USERPROFILE;
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
});
afterAll(() => {
  process.env.HOME = origHome;
  process.env.USERPROFILE = origUserprofile;
  _resetConfigCache();
  fs.rmSync(home, { recursive: true, force: true });
});

const n9 = (f: string) => path.join(home, '.node9', f);
const keyed = () =>
  fs.writeFileSync(n9('credentials.json'), JSON.stringify({ default: { apiKey: 'n9_test_ws' } }));
const cache = (body: Record<string, unknown>) =>
  fs.writeFileSync(
    n9('rules-cache.json'),
    JSON.stringify({ fetchedAt: '2026-10-04T00:00:00Z', rules: [], ...body })
  );

beforeEach(() => {
  for (const f of fs.readdirSync(n9(''))) fs.rmSync(n9(f), { force: true });
  _resetConfigCache();
});

describe('extractWorkspaceConfig', () => {
  it('keeps valid, settable entries and drops the rest', () => {
    const out = extractWorkspaceConfig({
      config: {
        version: '2',
        checks: {
          'commands.sudo': 'off',
          'data.pii': 'block',
          'data.canary': 'off',
          'commands.nope': 'off',
          'commands.chmod': 'maybe',
          'network.metadata': 'off',
        },
      },
    });
    expect(out).toEqual({ checks: { 'commands.sudo': 'off', 'data.pii': 'block' } });
  });
  it('answers undefined for a body without config, or with nothing usable', () => {
    expect(extractWorkspaceConfig({})).toBeUndefined();
    expect(extractWorkspaceConfig({ config: { version: '2' } })).toBeUndefined();
    expect(
      extractWorkspaceConfig({ config: { checks: { 'data.canary': 'off' } } })
    ).toBeUndefined();
  });
});

describe('a keyed machine with workspace checks', () => {
  it('takes them into policy.checks with source workspace, and the engine honours them', async () => {
    keyed();
    cache({ config: { checks: { 'commands.sudo': 'off', 'commands.chmod': 'block' } } });
    const c = getConfig();
    expect(c.policySource).toBe('workspace');
    expect(c.policy.checks?.['commands.sudo']).toBe('off');
    expect(c.policy.checks?.['commands.chmod']).toBe('block');
    expect(c.policy.checkSources).toEqual({
      'commands.sudo': 'workspace',
      'commands.chmod': 'workspace',
    });
    const v = await evaluatePolicy('bash', { command: 'sudo apt-get install jq' }, 'Claude Code');
    expect(v.decision).toBe('allow');
    const row = buildChecksReport(c).checks.find((r) => r.id === 'commands.sudo');
    expect(row).toMatchObject({ value: 'off', source: 'workspace' });
  });

  it('ignores the local v2 file entirely', () => {
    keyed();
    cache({ config: { checks: { 'commands.sudo': 'review' } } });
    fs.writeFileSync(
      n9('config.json'),
      JSON.stringify({ version: '2', checks: { 'commands.sudo': 'off', 'commands.rm': 'off' } })
    );
    const c = getConfig();
    expect(c.policy.checks?.['commands.sudo']).toBe('review');
    expect(c.policy.checks?.['commands.rm']).toBe('review');
    expect(c.policy.checkSources).toEqual({ 'commands.sudo': 'workspace' });
  });

  it('a body without config behaves exactly as before', () => {
    keyed();
    cache({ managedConfig: { commandChecks: { inlineExec: 'off' }, locked: [] } });
    const c = getConfig();
    expect(c.policy.commandChecks?.inlineExec).toBe('off');
    expect(c.policy.checks?.['commands.inline-exec']).toBe('off');
    expect(c.policy.checkSources).toEqual({});
  });

  it('a hand-edited cache cannot smuggle a locked or unknown check', () => {
    keyed();
    cache({ config: { checks: { 'network.metadata': 'off', 'commands.nope': 'off' } } });
    const c = getConfig();
    expect(c.policy.checks?.['network.metadata']).toBe('block');
    expect(c.policy.checkSources).toEqual({});
  });
});

describe('an unkeyed machine', () => {
  it('does not read the workspace checks from a stale cache', () => {
    cache({ config: { checks: { 'commands.sudo': 'off' } } });
    const c = getConfig();
    expect(c.policySource).toBe('local');
    expect(c.policy.checks?.['commands.sudo']).toBe('review');
  });
});
