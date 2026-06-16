// src/posture/privilege.ts
// Check 5 — Privilege.
//
// Two signals: is the agent process running as root, and is privilege
// escalation (`sudo`) gated by the policy? The sudo probe runs through the
// REAL `evaluatePolicy` (classifier-only, never executed) — same gate the
// in-path enforcement uses.

import { evaluatePolicy } from '../policy';
import type { CheckContext, Finding } from './types';

// A clearly-privileged, clearly-destructive command used ONLY as classifier
// input to test whether the gate blocks privilege escalation. Never executed.
const SUDO_PROBE = 'sudo chmod 777 /etc/passwd';

export async function checkPrivilege(ctx: CheckContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  const isRoot = uid === 0;
  if (isRoot) {
    findings.push({
      category: 'Privilege',
      severity: 'high',
      title: 'Running as root',
      what: 'The agent process is running as root (full system rights).',
      why: 'It was started as uid 0.',
      who: 'One bad command can change any file, user, or service on the machine.',
      detail: [],
      fix: 'node9 can block privileged commands (sudo, system-path writes) in-path.',
    });
  }

  const verdict = await evaluatePolicy('Bash', { command: SUDO_PROBE }, ctx.agent, ctx.cwd);
  if (verdict.decision !== 'block') {
    findings.push({
      category: 'Privilege',
      severity: isRoot ? 'high' : 'medium',
      title: 'Privilege escalation is not gated',
      what: "node9 isn't gating `sudo`.",
      why: 'No sudo rule is active in the current policy.',
      // Calibrated: don't claim the agent CAN become root — it depends on sudo config.
      who: 'If `sudo` is passwordless (NOPASSWD), an agent could become root; with a password prompt the risk is lower.',
      detail: [],
      fix: 'node9 can gate sudo / privilege-escalation in-path.',
      // Coverage probes the real policy: block OR review = gated (covered).
      coverageProbe: { kind: 'command', command: SUDO_PROBE },
    });
  }

  return findings;
}
