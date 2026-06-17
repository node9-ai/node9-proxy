// src/posture/coverage.ts
// Check 7 — Coverage (the meta-check).
//
// Everything else on the card is only as real as node9's actual presence in
// the loop. Two questions: is node9 wired into ANY agent on this box, and —
// if so — is it ENFORCING (blocking) or just watching (observe/audit)?

import os from 'os';
import { getConfig } from '../config';
import { getAgentWiring } from '../agent-wiring';
import type { CheckContext, Finding } from './types';

export function checkCoverage(ctx: CheckContext): Finding[] {
  const home = ctx.home || os.homedir();
  const findings: Finding[] = [];

  // Is node9 in-path for any agent at all?
  const protectedAgents = getAgentWiring(home).filter((r) => r.isProtected);
  if (protectedAgents.length === 0) {
    findings.push({
      category: 'Coverage',
      severity: 'critical',
      title: 'node9 is not in-path for any agent',
      what: "node9 isn't actually in the loop for any agent on this machine.",
      why: 'No agent has node9 hooks or MCP wired in.',
      who: 'Everything else here is unenforced — node9 can only report, not block.',
      detail: [],
      owner: 'node9',
      fix: 'Run `node9 init` to put node9 in-path for your agents.',
    });
    return findings; // nothing downstream matters if node9 isn't wired
  }

  // Wired — but enforcing, or only observing?
  const mode = getConfig(ctx.cwd).settings.mode;
  if (mode === 'observe' || mode === 'audit') {
    findings.push({
      category: 'Coverage',
      severity: 'high',
      title: `node9 is in ${mode} mode — watching, not blocking`,
      what: 'node9 is watching but not actually blocking anything.',
      why: `It's in ${mode} mode, which logs risky actions but lets them through.`,
      who: 'The guardrails above are observed, not enforced.',
      detail: [],
      owner: 'node9',
      fix: 'Set mode to `standard` (or `strict`) to enforce in-path.',
    });
  }

  return findings;
}
