// src/posture/coverage.ts
// Check 7 — Coverage (the meta-check).
//
// Everything else on the card is only as real as node9's actual presence in
// the loop. Two questions: is node9 wired into ANY agent on this box, and —
// if so — is it ENFORCING (blocking) or just watching (observe/audit)?

import os from 'os';
import { getConfig } from '../config';
import { isRecordOnly, levelOf } from '@node9/policy-engine';
import { getAgentWiring } from '../agent-wiring';
import { autostartState } from '../daemon/service';
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
  const config = getConfig(ctx.cwd);
  const mode = config.settings.mode;
  if (isRecordOnly(mode)) {
    // One name for the level in every report (fw#421): the config may still
    // say `observe`, the user reads `audit`, as `status` prints it.
    const level = levelOf(mode);
    findings.push({
      category: 'Coverage',
      severity: 'high',
      title: `node9 is in ${level} mode — watching, not blocking`,
      what: 'node9 is watching but not actually blocking anything.',
      why: `It's in ${level} mode, which logs risky actions but lets them through.`,
      who: 'The guardrails above are observed, not enforced.',
      detail: [],
      owner: 'node9',
      fix: 'Set mode to `standard` (or `strict`) to enforce in-path.',
    });
  }

  // Self-protection (OWASP ASI10): a guard that does not come back after a
  // reboot leaves the next sessions ungoverned until someone notices.
  if (config.settings.autoStartDaemon !== false) {
    const state = autostartState();
    if (state === 'disabled' || state === 'absent') {
      findings.push({
        category: 'Coverage',
        severity: 'medium',
        title: "node9's daemon will not start after a reboot",
        what: 'The daemon that answers approvals and syncs the policy is not registered to start with the machine.',
        why:
          state === 'absent'
            ? 'No autostart entry is installed for it.'
            : 'Its autostart entry is installed but disabled.',
        who: 'After the next reboot, approvals time out and the policy stops syncing until the daemon is started by hand.',
        detail: [],
        owner: 'node9',
        fix: 'Run `node9 doctor` to install and enable the autostart entry.',
      });
    }
  }

  return findings;
}
