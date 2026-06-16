// src/posture/egress.ts
// Check 2 — Egress / exfiltration.
//
// Reads the SAME egress-control state the in-path gate enforces
// (`config.policy.egress`). No live network probing — config inspection only.

import { getConfig } from '../config';
import type { CheckContext, Finding } from './types';

interface EgressConfig {
  enabled: boolean;
  mode: 'off' | 'review' | 'block';
}

/** Pure verdict so the logic is unit-testable without a config file. */
export function evaluateEgressConfig(egress: EgressConfig): Finding | null {
  // Locked down: enabled, blocking unknown hosts, with an allowlist.
  if (egress.enabled && egress.mode === 'block') return null;

  if (egress.enabled && egress.mode === 'review') {
    return {
      category: 'Egress',
      severity: 'medium',
      title: 'Egress is logged but not blocked',
      detail: [
        'Mode is `review`: outbound destinations are recorded, not stopped.',
        'A compromised agent can still exfiltrate to any host.',
      ],
      fix: 'node9 can switch egress to `block` with a host allowlist.',
      coverageProbe: { kind: 'egress' },
    };
  }

  // disabled, or enabled with mode 'off'
  return {
    category: 'Egress',
    severity: 'high',
    title: 'Egress is open',
    detail: ['The agent can reach any host on the internet — an open exfiltration path.'],
    fix: 'node9 can lock egress to an allowlist (policy.egress.mode = block).',
    coverageProbe: { kind: 'egress' },
  };
}

export function checkEgress(ctx: CheckContext): Finding[] {
  const config = getConfig(ctx.cwd);
  const egress = config.policy.egress;
  const finding = evaluateEgressConfig({ enabled: egress.enabled, mode: egress.mode });
  return finding ? [finding] : [];
}
