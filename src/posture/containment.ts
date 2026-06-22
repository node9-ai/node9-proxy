// src/posture/containment.ts
// Check — Isolation (ADVISORY).
//
// Advisory severity (does NOT deduct from the score). node9 now offers the full
// remediation — `node9 sandbox run` jails the agent in a disposable container,
// governed + audited inside — alongside the without-a-container mitigations
// (project-jail, egress lock). The fix text leads with the sandbox on-ramp.
//
// (Inbound exposure moved to inbound.ts so it can identify the listening
// process and avoid over-claiming. See inbound.ts.)
//
// Linux-only signals (/.dockerenv, /proc). On other platforms these read empty.

import fs from 'fs';
import type { CheckContext, Finding } from './types';

/** Points the unsandboxed-host gap deducts while open. The biggest single
 *  hardening lever (sandbox closes it); tuned so a clean-but-unsandboxed host
 *  reads ~84 "Good — hardening available", not a contradictory 100. */
export const ISOLATION_WEIGHT = 12;

/** True when the process appears to run inside a container. */
function inContainer(): boolean {
  if (fs.existsSync('/.dockerenv') || fs.existsSync('/run/.containerenv')) return true;
  try {
    const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf8');
    if (/docker|kubepods|containerd|lxc|libpod/.test(cgroup)) return true;
  } catch {
    /* no /proc — not Linux, or unreadable */
  }
  return false;
}

export function checkContainment(_ctx: CheckContext): Finding[] {
  if (inContainer()) return [];

  return [
    {
      category: 'Isolation',
      severity: 'advisory',
      title: 'Running directly on the host — no container',
      what: 'The agent runs loose on your whole machine, not in a sandbox.',
      why: "It's started on the bare host, not inside a container or VM.",
      who: 'If it gets tricked, the damage reaches every file and program — not one room.',
      detail: [],
      owner: 'os',
      node9Reduces: true,
      // The single biggest hardening gap, and node9 now fully remedies it
      // (`node9 sandbox run`). Deducts while open; closing it is the headline
      // payoff. No coverageProbe → stays OPEN (scored) until adopted; live
      // partial-credit for the lighter shield path is a fast-follow.
      scoreWeight: ISOLATION_WEIGHT,
      gain: 'jailed container · kernel egress wall · scoped mounts · governed inside',
      cost: 'the agent works inside /workspace, not your live host',
      fix:
        'Two ways to shrink the blast radius — pick by how much flexibility you need:\n' +
        `Strongest — jail it (closes this gap, +${ISOLATION_WEIGHT}):\n` +
        '  • node9 sandbox run <agent>\n' +
        `Lighter — harden in place, keep full host access (about +${Math.round(
          ISOLATION_WEIGHT / 2
        )}):\n` +
        '  • node9 shield enable project-jail — block stray credential reads\n' +
        '  • node9 egress lock — block data exfil',
    },
  ];
}
