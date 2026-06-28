// src/policy-snapshot/build.ts
// Config mirror (Phase 1b): builds the EFFECTIVE local policy the proxy ships
// to the SaaS so the dashboard can SEE what this machine enforces. Pure +
// exported so the caps + field mapping are testable without the network.
//
// Policy, not secrets: smartRules are regexes/verdicts, the egress allowlist is
// hostnames — the same class of data BlastSnapshot already ships. Arrays are
// capped to mirror the SaaS zod schema (a valid build never gets 400'd);
// smartRuleCount carries the true total so truncation stays honest.

import type { Config } from '../config/index.js';
import type { ShieldOverrides } from '@node9/policy-engine';
import { ENGINE_VERSION } from '@node9/policy-engine';

const MAX_RULES = 500;
const MAX_EGRESS = 200;

export interface PolicySnapshotBody {
  mode: string;
  panicMode: boolean;
  shadowMode: boolean;
  activeShields: string[];
  shieldOverrides: ShieldOverrides;
  smartRuleCount: number;
  smartRules: Array<{
    name?: string;
    tool?: string;
    verdict?: string;
    reason?: string;
  }>;
  egress: { enabled: boolean; mode: string; allow: string[] };
  dlpEnabled: boolean;
  engineVersion: string;
}

export function buildPolicySnapshot(
  config: Config,
  activeShields: string[],
  overrides: ShieldOverrides
): PolicySnapshotBody {
  const p = config.policy;
  return {
    mode: config.settings.mode,
    panicMode: config.settings.panicMode === true,
    // The proxy expresses shadow/observe as mode === 'observe' (cloud shadowMode
    // forces it); there's no separate settings flag.
    shadowMode: config.settings.mode === 'observe',
    activeShields,
    shieldOverrides: overrides,
    smartRuleCount: p.smartRules.length,
    smartRules: p.smartRules.slice(0, MAX_RULES).map((r) => ({
      name: r.name,
      tool: r.tool,
      verdict: r.verdict,
      reason: r.reason,
    })),
    egress: {
      enabled: p.egress.enabled,
      mode: p.egress.mode,
      allow: p.egress.allow.slice(0, MAX_EGRESS),
    },
    dlpEnabled: p.dlp.enabled,
    engineVersion: ENGINE_VERSION,
  };
}
