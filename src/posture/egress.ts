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

/**
 * Pure verdict. Always emits an Egress finding now (never null) — coverage
 * (annotateCoverage's egress probe, gated on enforcing) decides covered vs
 * open. So a locked + enforcing egress renders 🟢 covered (consistent with
 * Secrets/Privilege), not ✅ passed.
 */
export function evaluateEgressConfig(egress: EgressConfig): Finding {
  // Locked: when node9 is enforcing this becomes 🟢 covered; if node9 ISN'T
  // enforcing (not wired / observe), it surfaces as open below via coverage —
  // honest, because a lock that isn't applied protects nothing.
  if (egress.enabled && egress.mode === 'block') {
    return {
      category: 'Egress',
      severity: 'high',
      title: 'Egress is locked, but node9 is not enforcing it',
      what: 'Egress is set to block, but node9 is not applying the policy.',
      why: "node9 isn't wired in (or is in observe mode), so the lock has no effect.",
      who: 'The lock protects nothing until node9 is enforcing in-path.',
      owner: 'node9',
      detail: [],
      fix: 'Run `node9 setup` and ensure node9 is in enforcing mode.',
      coverageProbe: { kind: 'egress' },
      // Open here means only "node9 isn't enforcing" — Coverage already says
      // that, so drop this row when open to avoid double-surfacing.
      redundantWhenOpen: true,
    };
  }

  // Review (watch): node9 approval-gates outbound to unknown hosts — at runtime
  // a non-allowlisted destination routes to the approval race engine, so the
  // user catches exfil. When node9 is enforcing this is 🟢 covered (level
  // 'review' → "approval-gating"); only when node9 ISN'T enforcing does it
  // surface as open (and drops, since Coverage already reports the wiring gap).
  if (egress.enabled && egress.mode === 'review') {
    return {
      category: 'Egress',
      severity: 'medium',
      title: 'Egress is in review, but node9 is not enforcing it',
      what: 'Egress is set to review (approval-gate), but node9 is not applying the policy.',
      why: "node9 isn't wired in (or is in observe mode), so the gate has no effect.",
      who: 'Nothing gates outbound until node9 is enforcing in-path.',
      owner: 'node9',
      detail: [],
      fix: 'Run `node9 setup` and ensure node9 is in enforcing mode.',
      coverageProbe: { kind: 'egress' },
      // Open here means only "node9 isn't enforcing" — Coverage already says
      // that, so drop this row when open to avoid double-surfacing.
      redundantWhenOpen: true,
    };
  }

  // disabled, or enabled with mode 'off'
  return {
    category: 'Egress',
    severity: 'high',
    title: 'Egress is open',
    what: 'Your agent can connect to any server on the internet.',
    why: "node9 isn't restricting where its network tools (curl, wget, ssh) can reach.",
    who: 'If the agent is ever tricked, nothing stops it sending your data out.',
    owner: 'node9',
    detail: [],
    fix: 'Fix it now: run `node9 egress watch` (or `node9 egress lock` to hard-block).',
    coverageProbe: { kind: 'egress' },
  };
}

export function checkEgress(ctx: CheckContext): Finding[] {
  const config = getConfig(ctx.cwd);
  const egress = config.policy.egress;
  return [evaluateEgressConfig({ enabled: egress.enabled, mode: egress.mode })];
}
