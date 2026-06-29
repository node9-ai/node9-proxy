import { describe, it, expect } from 'vitest';
import { buildPolicySnapshot } from './build';
import { ENGINE_VERSION } from '@node9/policy-engine';
import type { Config } from '../config/index';

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
});
