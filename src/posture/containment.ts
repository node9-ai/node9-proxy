// src/posture/containment.ts
// Check — Isolation (ADVISORY).
//
// Detect-only: node9 can read this but cannot fix it (the remediation is a
// container/VM, not node9), so the finding is `advisory` severity and does NOT
// deduct from the score. It's the honest line that sets up the enforcement
// story: node9 protects what runs INSIDE the box you still have to harden.
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
      fix: 'Run the agent in a container/VM; node9 enforces the policy within it.',
      coverageProbe: { kind: 'cantFix' },
    },
  ];
}
