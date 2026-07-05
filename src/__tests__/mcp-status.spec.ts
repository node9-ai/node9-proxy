// P3 2.6 follow-up — the merged "configured vs connected" status model.
// The load-bearing case: a config upstream carries an ${ENV} placeholder, but the
// running gateway keys mcp-tools.json by the SUBSTITUTED command. The resolver
// must substitute BEFORE hashing or the join silently misses (reproduces the
// exact redis-dev situation from the live session).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { substituteEnv, resolveEntryStatus, STALE_MS } from '../mcp-status';
import { getServerKey } from '../mcp-pin';
import type { McpEntry } from '../mcp-wrap';
import type { McpToolsConfig } from '../daemon/mcp-tools';

const NOW = 1_800_000_000_000; // fixed epoch-ms for deterministic age math

function gatewayed(name: string, upstream: string): McpEntry {
  const raw = { command: 'node9', args: ['mcp-gateway', '--upstream', upstream] };
  return {
    agent: 'claude',
    agentLabel: 'Claude Code',
    mcpFile: '/x/.claude.json',
    format: 'json',
    name,
    command: 'node9',
    args: raw.args,
    state: 'gatewayed',
    raw,
  };
}

function connectedTools(upstream: string, lastSeenAt?: number): McpToolsConfig {
  // Mirror what the gateway writes: keyed by getServerKey(<resolved upstream>).
  const key = getServerKey(upstream);
  return {
    [key]: {
      tools: [{ name: 'get' }, { name: 'set' }, { name: 'delete' }, { name: 'list' }],
      disabled: [],
      status: 'approved',
      ...(lastSeenAt !== undefined && { lastSeenAt }),
    },
  };
}

describe('substituteEnv', () => {
  it('substitutes a set var, applies a :- default when unset, flags a bare unset var', () => {
    const r1 = substituteEnv('a ${FOO} b', { FOO: 'X' });
    expect(r1).toEqual({ resolved: 'a X b', missing: [] });

    const r2 = substituteEnv('u ${BAR:-fallback}', {});
    expect(r2).toEqual({ resolved: 'u fallback', missing: [] });

    const r3 = substituteEnv('u ${BAZ}', {});
    expect(r3).toEqual({ resolved: 'u ', missing: ['BAZ'] });
  });

  it('treats an empty-string var as needing a value (missing / default applies)', () => {
    expect(substituteEnv('${E}', { E: '' }).missing).toEqual(['E']);
    expect(substituteEnv('${E:-d}', { E: '' })).toEqual({ resolved: 'd', missing: [] });
  });

  it('dedups repeated missing vars', () => {
    expect(substituteEnv('${A} ${A}', {}).missing).toEqual(['A']);
  });
});

describe('resolveEntryStatus', () => {
  const REDIS = 'npx -y @modelcontextprotocol/server-redis';

  it('joins a placeholder upstream to its connected entry AFTER env substitution (redis-dev)', () => {
    // Config carries the raw placeholder; the connected entry is keyed by the
    // resolved command. A naive hash of the raw string would NOT match.
    const upstreamCfg = `${REDIS} \${REDIS_DEV_URL:-redis://localhost:6379}`;
    const upstreamRun = `${REDIS} redis://localhost:6379`;
    const e = gatewayed('redis-dev', upstreamCfg);
    const tools = connectedTools(upstreamRun, NOW - 120_000); // 2m ago

    const out = resolveEntryStatus(e, tools, {}, NOW);
    expect(out.connection).toBe('connected');
    expect(out.serverKey).toBe(getServerKey(upstreamRun));
    expect(out.connectedTools).toBe(4);
    expect(out.lastSeenAt).toBe(NOW - 120_000);
  });

  it('flags a bare unset ${VAR} as unlaunchable — NOT pending-launch (redis-prod)', () => {
    const e = gatewayed('redis-prod', `${REDIS} \${REDIS_PROD_URL}`);
    const out = resolveEntryStatus(e, {}, {}, NOW);
    expect(out.connection).toBe('unlaunchable');
    expect(out.missingEnv).toEqual(['REDIS_PROD_URL']);
    expect(out.serverKey).toBeUndefined(); // can't key an unlaunchable server
  });

  it('a resolvable-but-never-launched server is pending-launch (governed, empty tools)', () => {
    const upstream = `${REDIS} redis://localhost:6379`;
    const e = gatewayed('redis-dev', upstream);
    const out = resolveEntryStatus(e, {}, {}, NOW); // nothing connected yet
    expect(out.connection).toBe('pending-launch');
    expect(out.serverKey).toBe(getServerKey(upstream)); // key IS known — it just hasn't run
  });

  it('a governed server not seen within STALE_MS is stale', () => {
    const upstream = `${REDIS} redis://localhost:6379`;
    const e = gatewayed('redis-dev', upstream);
    const tools = connectedTools(upstream, NOW - (STALE_MS + 1));
    expect(resolveEntryStatus(e, tools, {}, NOW).connection).toBe('stale');
  });

  it('a connected entry with no lastSeenAt (legacy build) counts as connected, not stale', () => {
    const upstream = `${REDIS} redis://localhost:6379`;
    const e = gatewayed('redis-dev', upstream);
    const tools = connectedTools(upstream); // undated
    const out = resolveEntryStatus(e, tools, {}, NOW);
    expect(out.connection).toBe('connected');
    expect(out.lastSeenAt).toBeUndefined();
  });

  it('passes through non-governed classes unchanged', () => {
    const self: McpEntry = { ...gatewayed('node9', 'x'), state: 'node9-self' };
    const remote: McpEntry = { ...gatewayed('r', 'x'), state: 'remote' };
    const ung: McpEntry = { ...gatewayed('u', 'x'), state: 'ungoverned' };
    expect(resolveEntryStatus(self, {}, {}, NOW).connection).toBe('node9-self');
    expect(resolveEntryStatus(remote, {}, {}, NOW).connection).toBe('remote');
    expect(resolveEntryStatus(ung, {}, {}, NOW).connection).toBe('ungoverned');
  });

  it('a gatewayed entry with a corrupt (missing) --upstream is pending-launch, never crashes', () => {
    const e = gatewayed('broken', 'x');
    e.args = ['mcp-gateway']; // hand-corrupted: no --upstream
    expect(resolveEntryStatus(e, {}, {}, NOW).connection).toBe('pending-launch');
  });

  // R1 Layer 1 — identity-join: a launched server stamped with its config key is
  // connected via ground truth, WITHOUT resolving env (the daemon-env-differs bug).
  const stampedTools = (name: string, key = 'realkey123', lastSeenAt = NOW): McpToolsConfig => ({
    [key]: { name, tools: [{ name: 'get' }], disabled: [], status: 'approved', lastSeenAt },
  });

  it('identity-join: a config-key-stamped server is CONNECTED even when env is unresolvable (R1 live repro)', () => {
    // config upstream needs ${REDIS_PROD_URL} (unset here) — the legacy path would
    // short-circuit to `unlaunchable`. But a connected entry is stamped "redis-prod".
    const e = gatewayed('redis-prod', 'npx -y @x/server-redis ${REDIS_PROD_URL}');
    const out = resolveEntryStatus(e, stampedTools('redis-prod'), {}, NOW); // env {} — no var
    expect(out.connection).toBe('connected');
    expect(out.serverKey).toBe('realkey123');
    expect(out.connectedTools).toBe(1);
  });

  it('identity-join reports stale when the stamped entry is old', () => {
    const e = gatewayed('redis-prod', 'npx -y @x/server-redis ${REDIS_PROD_URL}');
    const out = resolveEntryStatus(
      e,
      stampedTools('redis-prod', 'k', NOW - (STALE_MS + 1)),
      {},
      NOW
    );
    expect(out.connection).toBe('stale');
  });

  it('UNstamped (name mismatch) falls through to the env path — no regression', () => {
    // connected entry still carries the derived name "redis", not the config key.
    const e = gatewayed('redis-prod', 'npx -y @x/server-redis ${REDIS_PROD_URL}');
    const out = resolveEntryStatus(e, stampedTools('redis'), {}, NOW); // env {} → env path
    expect(out.connection).toBe('unlaunchable');
    expect(out.missingEnv).toContain('REDIS_PROD_URL');
  });
});

// The freshness stamp the resolver relies on — proven against the REAL writer
// (updateServerDiscovery), which the gateway calls on every discovery report.
describe('updateServerDiscovery stamps lastSeenAt', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-mcpstatus-'));
    vi.spyOn(os, 'homedir').mockReturnValue(home);
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('stamps on new AND refreshes on a matching re-report', async () => {
    const mod = await import('../daemon/mcp-tools.js');
    const tools = [{ name: 'get' }, { name: 'set' }];

    expect(mod.updateServerDiscovery('k1', tools)).toBe('new');
    const first = mod.readMcpToolsConfig()['k1'].lastSeenAt;
    expect(typeof first).toBe('number');

    // A later identical report → 'match', but lastSeenAt must still advance
    // (proves the server is connected NOW, not just historically).
    vi.spyOn(Date, 'now').mockReturnValue((first as number) + 5000);
    expect(mod.updateServerDiscovery('k1', tools)).toBe('match');
    expect(mod.readMcpToolsConfig()['k1'].lastSeenAt).toBe((first as number) + 5000);
  });

  // P2.2 — a re-wrap reports a config name that must REPLACE the derived one
  // (was backfill-only; that would have made the rename silently no-op).
  it('overwrites a previously-reported name with a newly reported one', async () => {
    const mod = await import('../daemon/mcp-tools.js');
    const tools = [{ name: 'get' }];
    mod.updateServerDiscovery('k2', tools, 'redis'); // first launch: derived name
    expect(mod.readMcpToolsConfig()['k2'].name).toBe('redis');
    mod.updateServerDiscovery('k2', tools, 'redis-dev'); // re-wrap: config name
    expect(mod.readMcpToolsConfig()['k2'].name).toBe('redis-dev');
  });
});
