// src/posture/inbound.ts
// Check — Inbound exposure (ADVISORY).
//
// Splits "something is listening on 0.0.0.0" into two HONEST findings instead
// of the old over-claiming "anyone can pilot your agent":
//
//   • Network exposure   — a service (Postgres/Redis/dev server/unknown
//                          process) reachable from other hosts. Real, but it's
//                          "your data/box is exposed", not "your agent is run".
//   • Agent inbound      — emitted ONLY when a listener can be tied to the
//                          named agent (--agent). Then the "pilot it" claim is
//                          actually true: whoever reaches the port can instruct it.
//
// Process identity comes from /proc/net/tcp[6] (socket inode) → /proc/<pid>/fd
// (which fd points at socket:[inode]) → /proc/<pid>/comm + cmdline. Linux-only;
// resolves the current user's processes (system-daemon sockets fall back to the
// port map). Read-only — no socket is opened or probed.

import fs from 'fs';
import type { CheckContext, Finding } from './types';

interface Listener {
  port: number;
  inode: string;
}

interface ProcInfo {
  comm: string;
  cmdline: string;
}

// Well-known service ports — used even when the owning process can't be read
// (e.g. Postgres running as the `postgres` user, not us).
const KNOWN_SERVICE_PORTS: Record<number, string> = {
  5432: 'PostgreSQL',
  6379: 'Redis',
  3306: 'MySQL/MariaDB',
  27017: 'MongoDB',
  9200: 'Elasticsearch',
  11211: 'Memcached',
  5672: 'RabbitMQ',
  9092: 'Kafka',
  2379: 'etcd',
  8086: 'InfluxDB',
};

// Process-name → service, for non-standard ports.
const KNOWN_SERVICE_COMMS: Record<string, string> = {
  postgres: 'PostgreSQL',
  'redis-server': 'Redis',
  mysqld: 'MySQL',
  mariadbd: 'MariaDB',
  mongod: 'MongoDB',
};

const DB_LABEL = /PostgreSQL|Redis|MySQL|MariaDB|MongoDB/;

/**
 * Parse `/proc/net/tcp(6)` into the listeners bound to all interfaces
 * (0.0.0.0 / ::), with their socket inode. Exported pure for testing.
 */
export function parseListeners(procText: string): Listener[] {
  const out: Listener[] = [];
  for (const line of procText.split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 10) continue; // need through the inode column (idx 9)
    if (cols[3] !== '0A') continue; // 0A = TCP_LISTEN
    const local = cols[1];
    const sep = local.lastIndexOf(':');
    if (sep < 0) continue;
    const addrHex = local.slice(0, sep);
    const port = parseInt(local.slice(sep + 1), 16);
    if (!/^0+$/.test(addrHex) || !Number.isFinite(port)) continue; // all-zero addr only
    out.push({ port, inode: cols[9] });
  }
  return out;
}

/**
 * True only when the listening process can be confidently tied to the named
 * agent. Guards against re-introducing the "anyone can pilot your agent"
 * over-claim: a generic name (e.g. --agent node) must not match every node
 * process. Requires a reasonably specific name (≥4 chars) matched on a
 * word/path boundary, not a bare substring (so 'herm' won't match 'thermal').
 */
function tiesToAgent(proc: ProcInfo, agentName: string): boolean {
  const needle = agentName.trim().toLowerCase();
  if (needle.length < 4) return false;
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const boundary = new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`);
  return boundary.test(proc.comm.toLowerCase()) || boundary.test(proc.cmdline.toLowerCase());
}

/**
 * Classify one listener. Pure + exported for testing. We only claim "agent"
 * when the process can be tied to the named agent — otherwise it's exposure.
 */
export function classifyListener(
  port: number,
  proc: ProcInfo | null,
  agentName?: string
): { kind: 'agent' | 'service' | 'unknown'; label: string } {
  if (agentName && proc && tiesToAgent(proc, agentName)) {
    return { kind: 'agent', label: `${proc.comm} on :${port}` };
  }
  const service = KNOWN_SERVICE_PORTS[port] ?? (proc ? KNOWN_SERVICE_COMMS[proc.comm] : undefined);
  if (service) return { kind: 'service', label: `${service} on :${port}` };
  return { kind: 'unknown', label: `${proc?.comm || 'unknown process'} on :${port}` };
}

function collectListeners(): Listener[] {
  const byPort = new Map<number, Listener>(); // dedupe tcp/tcp6 by port
  for (const file of ['/proc/net/tcp', '/proc/net/tcp6']) {
    try {
      for (const l of parseListeners(fs.readFileSync(file, 'utf8'))) {
        if (!byPort.has(l.port)) byPort.set(l.port, l);
      }
    } catch {
      /* absent — not Linux, or unreadable */
    }
  }
  return [...byPort.values()].sort((a, b) => a.port - b.port);
}

function readProc(pid: string): ProcInfo {
  let comm = 'unknown';
  let cmdline = '';
  try {
    // Strip Node's main-thread suffix so listeners read 'node', not
    // 'node-MainThread'.
    comm =
      fs
        .readFileSync(`/proc/${pid}/comm`, 'utf8')
        .trim()
        .replace(/-MainThread$/, '') || 'unknown';
  } catch {
    /* gone/forbidden */
  }
  try {
    cmdline = fs.readFileSync(`/proc/${pid}/cmdline`).toString().replace(/\0/g, ' ').trim();
  } catch {
    /* gone/forbidden */
  }
  return { comm, cmdline };
}

/** Map socket inodes → owning process by scanning /proc/<pid>/fd symlinks. */
function resolveProcesses(inodes: Set<string>): Map<string, ProcInfo> {
  const map = new Map<string, ProcInfo>();
  if (inodes.size === 0) return map;
  let pids: string[];
  try {
    pids = fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d));
  } catch {
    return map;
  }
  for (const pid of pids) {
    let fds: string[];
    try {
      fds = fs.readdirSync(`/proc/${pid}/fd`);
    } catch {
      continue; // EACCES (other user) / ESRCH (exited) — skip
    }
    for (const fd of fds) {
      let link: string;
      try {
        link = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
      } catch {
        continue;
      }
      const m = /^socket:\[(\d+)\]$/.exec(link);
      if (m && inodes.has(m[1]) && !map.has(m[1])) {
        map.set(m[1], readProc(pid));
      }
    }
    if (map.size === inodes.size) break; // all resolved
  }
  return map;
}

export function checkInbound(ctx: CheckContext): Finding[] {
  const listeners = collectListeners();
  if (listeners.length === 0) return [];

  const procByInode = resolveProcesses(new Set(listeners.map((l) => l.inode)));
  const classified = listeners.map((l) => ({
    port: l.port,
    ...classifyListener(l.port, procByInode.get(l.inode) ?? null, ctx.agent),
  }));

  const findings: Finding[] = [];

  const agentPorts = classified.filter((c) => c.kind === 'agent');
  if (agentPorts.length > 0) {
    findings.push({
      category: 'Agent inbound',
      severity: 'advisory',
      title: `Your agent is reachable on 0.0.0.0 (port${agentPorts.length === 1 ? '' : 's'} ${agentPorts
        .map((a) => a.port)
        .join(', ')})`,
      what: 'Your agent itself is listening for incoming network connections.',
      why: "It's bound to 0.0.0.0, so other devices on the network can reach it.",
      who: 'Anyone who can reach the port could send it instructions (pilot it). Confirm it requires an auth token.',
      detail: agentPorts.map((a) => a.label),
      fix: 'Bind the agent port to 127.0.0.1, or require an auth token on inbound requests.',
      coverageProbe: { kind: 'cantFix' },
    });
  }

  const exposed = classified.filter((c) => c.kind !== 'agent');
  if (exposed.length > 0) {
    const hasDb = exposed.some((e) => DB_LABEL.test(e.label));
    findings.push({
      category: 'Network exposure',
      severity: 'advisory',
      title: `${exposed.length} service${exposed.length === 1 ? '' : 's'} reachable on 0.0.0.0`,
      what: 'These services accept connections from your whole network, not just this laptop.',
      why: 'They listen on 0.0.0.0 (all interfaces) instead of 127.0.0.1 (this machine only).',
      // Calibrated: 0.0.0.0 = your local network (WiFi), not the public internet
      // unless the box has a public IP.
      who:
        'Other devices on your network (e.g. your WiFi) can connect — usually not the whole internet unless this box has a public IP.' +
        (hasDb ? ' An open, unauthenticated database is a direct data-theft path.' : ''),
      detail: exposed.map((e) => e.label),
      fix: 'Bind to 127.0.0.1 or firewall the port; node9 gates the agent, not the socket.',
      coverageProbe: { kind: 'cantFix' },
    });
  }

  return findings;
}
