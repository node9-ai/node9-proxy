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
      detail: [
        'The agent process is uid 0 — every command runs with full system rights.',
        'One bad command can modify any file, user, or service on the host.',
      ],
      fix: 'node9 can block privileged commands (sudo, system-path writes) in-path.',
    });
  }

  const verdict = await evaluatePolicy('Bash', { command: SUDO_PROBE }, ctx.agent, ctx.cwd);
  if (verdict.decision !== 'block') {
    findings.push({
      category: 'Privilege',
      severity: isRoot ? 'high' : 'medium',
      title: 'Privilege escalation is not gated',
      detail: [
        '`sudo` commands are not blocked by the current policy.',
        'An agent can escalate to root and step around file/command guards.',
      ],
      fix: 'node9 can block sudo / privilege-escalation in-path.',
      // Coverage probes the real policy: block OR review = gated (covered).
      coverageProbe: { kind: 'command', command: SUDO_PROBE },
    });
  }

  return findings;
}
