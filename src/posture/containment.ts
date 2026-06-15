// src/posture/containment.ts
// Check 6 — Containment (ADVISORY).
//
// Detect-only: node9 can read these but cannot fix them (the remediation is in
// the OS/infra, not node9), so findings are `advisory` severity and do NOT
// deduct from the score. They're the scariest, most honest lines on the card —
// "no container" and "listening on 0.0.0.0" — and they set up the enforcement
// story: node9 protects what runs INSIDE the box you still have to harden.
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

/**
 * Parse `/proc/net/tcp(6)` content into the set of ports LISTENing on all
 * interfaces (0.0.0.0 / ::). Exported pure for testing the hex parsing.
 */
export function parsePublicListeners(procText: string): number[] {
  const ports = new Set<number>();
  const lines = procText.split('\n').slice(1); // drop the header row
  for (const line of lines) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    const localAddr = cols[1];
    const state = cols[3];
    if (state !== '0A') continue; // 0A = TCP_LISTEN
    const sep = localAddr.lastIndexOf(':');
    if (sep < 0) continue;
    const addrHex = localAddr.slice(0, sep);
    const port = parseInt(localAddr.slice(sep + 1), 16);
    // All-zero address = bound to every interface (0.0.0.0 or ::).
    if (/^0+$/.test(addrHex) && Number.isFinite(port)) ports.add(port);
  }
  return [...ports].sort((a, b) => a - b);
}

function publicListeners(): number[] {
  const ports = new Set<number>();
  for (const file of ['/proc/net/tcp', '/proc/net/tcp6']) {
    try {
      for (const p of parsePublicListeners(fs.readFileSync(file, 'utf8'))) ports.add(p);
    } catch {
      /* absent — skip */
    }
  }
  return [...ports].sort((a, b) => a - b);
}

export function checkContainment(_ctx: CheckContext): Finding[] {
  const findings: Finding[] = [];

  if (!inContainer()) {
    findings.push({
      category: 'Isolation',
      severity: 'advisory',
      title: 'Running directly on the host — no container',
      detail: [
        'A compromised agent reaches the whole machine, not a sandbox.',
        'node9 can enforce inside a container, but cannot create the boundary.',
      ],
      fix: 'Run the agent in a container/VM; node9 enforces the policy within it.',
    });
  }

  const ports = publicListeners();
  if (ports.length > 0) {
    const shown = ports.slice(0, 6).join(', ');
    findings.push({
      category: 'Inbound',
      severity: 'advisory',
      title: `Listening on 0.0.0.0 — reachable externally (port${ports.length === 1 ? '' : 's'} ${shown})`,
      detail: [
        'A process is bound to all interfaces — other hosts can connect.',
        'If that process drives the agent, anyone reachable can pilot it.',
      ],
      fix: 'Bind to 127.0.0.1 or put it behind a firewall; node9 gates the agent, not the socket.',
    });
  }

  return findings;
}
