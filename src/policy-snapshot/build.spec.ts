import { describe, it, expect } from 'vitest';
import { buildPolicySnapshot } from './build';
import { ENGINE_VERSION } from '@node9/policy-engine';
import type { Config } from '../config/index';
import type { McpStatusEntry } from '../mcp-status';
import type { McpServerConfig } from '../daemon/mcp-tools';

// A connected mcp-tools.json entry (2 tools, approved).
const mkCfg = (): McpServerConfig => ({
  tools: [{ name: 'get' }, { name: 'set' }],
  disabled: [],
  status: 'approved',
});

function cfg(over: Record<string, unknown> = {}): Config {
  return {
    settings: { mode: 'standard', panicMode: false },
    policy: {
      smartRules: [],
      dlp: { enabled: true },
      egress: { enabled: false, mode: 'review', allow: [], deny: [] },
      ...((over.policy as object) ?? {}),
    },
    ...over,
  } as unknown as Config;
}

describe('buildPolicySnapshot', () => {
  it('maps mode, flags, dlp and the engine version', () => {
    const body = buildPolicySnapshot(cfg(), ['project-jail'], {});
    expect(body.mode).toBe('standard');
    expect(body.panicMode).toBe(false);
    expect(body.shadowMode).toBe(false);
    expect(body.dlpEnabled).toBe(true);
    expect(body.activeShields).toEqual(['project-jail']);
    expect(body.engineVersion).toBe(ENGINE_VERSION);
  });

  it('derives shadowMode from observe mode', () => {
    const body = buildPolicySnapshot(
      cfg({ settings: { mode: 'observe', panicMode: false } }),
      [],
      {}
    );
    expect(body.shadowMode).toBe(true);
  });

  it('caps smartRules but reports the true count', () => {
    const rules = Array.from({ length: 600 }, (_, i) => ({
      name: `r${i}`,
      tool: 'bash',
      conditions: [],
      verdict: 'block' as const,
      reason: 'x',
    }));
    const body = buildPolicySnapshot(
      cfg({
        policy: {
          smartRules: rules,
          dlp: { enabled: false },
          egress: { enabled: false, mode: 'review', allow: [], deny: [] },
        },
      }),
      [],
      {}
    );
    expect(body.smartRules).toHaveLength(500); // capped
    expect(body.smartRuleCount).toBe(600); // honest total
    // only the display subset is shipped
    expect(Object.keys(body.smartRules[0])).toEqual(['name', 'tool', 'verdict', 'reason']);
  });

  it('caps the egress allowlist', () => {
    const allow = Array.from({ length: 300 }, (_, i) => `h${i}.example.com`);
    const body = buildPolicySnapshot(
      cfg({
        policy: {
          smartRules: [],
          dlp: { enabled: false },
          egress: { enabled: true, mode: 'block', allow, deny: [] },
        },
      }),
      [],
      {}
    );
    expect(body.egress.enabled).toBe(true);
    expect(body.egress.mode).toBe('block');
    expect(body.egress.allow).toHaveLength(200);
  });

  it('maps the MCP inventory (key, tools, count, status) — connected by default', () => {
    const body = buildPolicySnapshot(
      cfg(),
      [],
      {},
      {
        srv123: {
          name: 'slack',
          tools: [{ name: 'slack_post' }, { name: 'slack_delete' }],
          disabled: [],
          status: 'approved',
        },
      }
    );
    expect(body.mcpServers).toEqual([
      {
        key: 'srv123',
        name: 'slack',
        tools: ['slack_post', 'slack_delete'],
        toolCount: 2,
        status: 'approved',
        connection: 'connected', // in mcp-tools.json ⇒ it launched
      },
    ]);
  });

  it('defaults mcpServers to [] when no inventory is passed', () => {
    expect(buildPolicySnapshot(cfg(), [], {}).mcpServers).toEqual([]);
  });

  // P2.1 — non-connected governed servers appear as SEE-only rows beside connected ones.
  const status = (over: Partial<McpStatusEntry>): McpStatusEntry =>
    ({
      agent: 'claude',
      agentLabel: 'Claude Code',
      name: 'x',
      state: 'gatewayed',
      connection: 'pending-launch',
      ...over,
    }) as McpStatusEntry;

  it('tags a connected row stale when the resolver says so (joined by serverKey)', () => {
    const body = buildPolicySnapshot(cfg(), [], {}, { srvA: mkCfg() }, [
      status({ name: 'redis', serverKey: 'srvA', connection: 'stale' }),
    ]);
    expect(body.mcpServers[0].connection).toBe('stale');
  });

  it('appends an unlaunchable row (tools: [], missingEnv) — governance-free', () => {
    const body = buildPolicySnapshot(cfg(), [], {}, {}, [
      status({
        name: 'redis-prod',
        connection: 'unlaunchable',
        missingEnv: ['REDIS_PROD_URL'],
      }),
    ]);
    expect(body.mcpServers).toEqual([
      {
        key: 'cfg:claude:redis-prod', // synthetic — no serverKey (can't resolve)
        name: 'redis-prod',
        tools: [],
        toolCount: 0,
        status: 'pending',
        connection: 'unlaunchable',
        missingEnv: ['REDIS_PROD_URL'],
      },
    ]);
  });

  it('does NOT duplicate a pending server whose serverKey is already connected', () => {
    const body = buildPolicySnapshot(cfg(), [], {}, { srvA: mkCfg() }, [
      // same key as the connected one — resolver briefly saw it as pending
      status({ name: 'redis', serverKey: 'srvA', connection: 'pending-launch' }),
    ]);
    expect(body.mcpServers).toHaveLength(1);
    expect(body.mcpServers[0].key).toBe('srvA');
    expect(body.mcpServers[0].connection).toBe('connected');
  });

  it('dedupes the same non-connected server wired in two agents', () => {
    const body = buildPolicySnapshot(cfg(), [], {}, {}, [
      status({ agent: 'claude', name: 'redis-prod', connection: 'unlaunchable' }),
      status({ agent: 'gemini', name: 'redis-prod', connection: 'unlaunchable' }),
    ]);
    // distinct synthetic keys (per-agent, on purpose) → two rows, not merged
    expect(body.mcpServers.map((s) => s.key)).toEqual([
      'cfg:claude:redis-prod',
      'cfg:gemini:redis-prod',
    ]);
  });

  // Review fix #4 — a daemon-env-differs push can mark an actually-connected
  // server 'unlaunchable' (it can't env-resolve the serverKey). If a connected
  // row shares the name (P2.2 config-name), suppress the phantom card.
  it('suppresses a non-connected row whose name matches a connected server', () => {
    const connected: Record<string, McpServerConfig> = {
      srvKey: { name: 'redis-dev', tools: [{ name: 'get' }], disabled: [], status: 'approved' },
    };
    const body = buildPolicySnapshot(cfg(), [], {}, connected, [
      // daemon couldn't resolve the env → no serverKey → would add an extra row,
      // but the connected row is named 'redis-dev' → drop the duplicate.
      status({ name: 'redis-dev', connection: 'unlaunchable', missingEnv: ['REDIS_DEV_URL'] }),
    ]);
    expect(body.mcpServers).toHaveLength(1);
    expect(body.mcpServers[0].key).toBe('srvKey');
    expect(body.mcpServers[0].connection).toBe('connected');
  });
});
