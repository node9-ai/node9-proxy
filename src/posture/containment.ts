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
      fix:
        'Full isolation — jail the agent in a disposable container, governed + audited inside:\n' +
        '  • node9 sandbox run <agent> — kernel-enforced egress + scoped mounts + node9 inside\n' +
        'Or shrink the blast radius without a container (you keep full host access):\n' +
        '  • node9 shield enable project-jail — block credential reads\n' +
        '  • node9 egress lock — block data exfil',
      coverageProbe: { kind: 'cantFix' },
    },
  ];
}
