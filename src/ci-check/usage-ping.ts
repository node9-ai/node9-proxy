// src/ci-check/usage-ping.ts
// The anonymous usage count `node9 scan-repo` sends after each run (fw#388).
//
// It answers one question: does anyone outside node9 run scan-repo, and from where
// (a terminal, their own CI job, or the node9 Action)? It never carries the target,
// a path, a finding or any code. Machines and repositories are sent as a random
// install id or a one-way hash, which the server keeps only inside a count.
//
// Off with NODE9_NO_TELEMETRY=1 or DO_NOT_TRACK=1, and always off under NODE9_TESTING.

import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import dns from 'node:dns';
import net from 'node:net';
import { getMachineId } from '../machine-id';
import { node9Version } from '../setup';
import { isLocalPath } from './fetch';
import type { ScanResult } from './types';

export type UsageSource = 'cli' | 'ci' | 'action';

export interface ScanRepoPing {
  event: 'scan_repo';
  source: UsageSource;
  node9_version: string;
  os: string;
  target_kind: 'github' | 'local';
  worst: 'none' | 'advisory' | 'medium' | 'high' | 'critical';
  incomplete: boolean;
  machine_id?: string;
  repo_hash?: string;
}

/** Shown on stderr after a terminal run, so nobody learns about the ping from a packet capture. */
export const SCAN_REPO_TELEMETRY_NOTICE =
  'node9 sends an anonymous usage count (no repo name, no code). Turn off: NODE9_NO_TELEMETRY=1';

const TRUTHY = /^(1|true|yes)$/i;

export function telemetryDisabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return (
    TRUTHY.test(env.NODE9_NO_TELEMETRY ?? '') ||
    TRUTHY.test(env.DO_NOT_TRACK ?? '') ||
    // Same rule as isTestingMode(), read from `env` so a test can pass its own.
    TRUTHY.test(env.NODE9_TESTING ?? '')
  );
}

/** Where this run comes from. Our action.yml says so explicitly; any other CI is `ci`. */
export function usageSource(env: NodeJS.ProcessEnv = process.env): UsageSource {
  if (env.NODE9_USAGE_SOURCE === 'action') return 'action';
  if (TRUTHY.test(env.CI ?? '') || TRUTHY.test(env.GITHUB_ACTIONS ?? '')) return 'ci';
  return 'cli';
}

export function buildScanRepoPing(
  res: ScanResult,
  target: string,
  env: NodeJS.ProcessEnv = process.env
): ScanRepoPing {
  const source = usageSource(env);
  const ping: ScanRepoPing = {
    event: 'scan_repo',
    source,
    node9_version: node9Version(),
    os: process.platform,
    target_kind: isLocalPath(target) ? 'local' : 'github',
    worst: res.worst ?? 'none',
    incomplete: res.incomplete,
  };
  if (source === 'cli') {
    ping.machine_id = getMachineId();
  } else {
    // A CI runner is usually fresh every time, so a machine id would count runs, not
    // users, and would leave a file on the runner. The repository's numeric id, hashed,
    // counts distinct repositories instead. Outside GitHub there is no id: no hash.
    const id = env.GITHUB_REPOSITORY_ID ?? '';
    if (/^\d+$/.test(id)) {
      ping.repo_hash = crypto.createHash('sha256').update(`node9-scan-repo:${id}`).digest('hex');
    }
  }
  return ping;
}

/** Where the ping goes. Only tests override it; the CLI call site never does. */
export interface PingTarget {
  hostname: string;
  port?: number;
  protocol: 'https' | 'http';
  /** DNS servers for the lookup. Tests only; production uses the system's. */
  dnsServers?: string[];
}

const PRODUCTION: PingTarget = { hostname: 'api.node9.ai', protocol: 'https' };

/**
 * Best effort: never throws, never writes to stdout, and resolves within `timeoutMs`
 * whatever the network does, so a blocked or slow endpoint costs the run at most that.
 */
export function sendScanRepoPing(
  ping: ScanRepoPing,
  timeoutMs = 1500,
  target: PingTarget = PRODUCTION
): Promise<void> {
  return new Promise((resolve) => {
    let req: http.ClientRequest | undefined;
    let settled = false;
    // The lookup goes through a c-ares resolver, not the default getaddrinfo: a
    // getaddrinfo call cannot be cancelled, so a resolver that never answers kept the
    // process alive for ~20 s after the scan had finished. This one is cancelled below.
    const resolver = new dns.Resolver({ timeout: Math.min(timeoutMs, 1000), tries: 1 });
    if (target.dnsServers) resolver.setServers(target.dnsServers);
    const cap = setTimeout(() => {
      req?.destroy();
      done();
    }, timeoutMs);
    function done(): void {
      if (settled) return;
      settled = true;
      clearTimeout(cap);
      resolver.cancel();
      resolve();
    }
    try {
      const body = JSON.stringify(ping);
      const request = target.protocol === 'https' ? https.request : http.request;
      req = request(
        {
          hostname: target.hostname,
          port: target.port,
          lookup: cancellableLookup(resolver),
          path: '/api/v1/telemetry',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (r) => {
          r.resume();
          r.on('end', done);
          r.on('error', done);
        }
      );
      req.on('error', done);
      req.on('close', done);
      req.end(body);
    } catch {
      done();
    }
  });
}

/** A `lookup` for http.request that resolves through `resolver` (IPv4 only). */
function cancellableLookup(resolver: dns.Resolver): net.LookupFunction {
  return (hostname, options, callback) => {
    const family = net.isIP(hostname);
    if (family) {
      if (options.all) callback(null, [{ address: hostname, family }]);
      else callback(null, hostname, family);
      return;
    }
    resolver.resolve4(hostname, (err, addresses) => {
      if (err || addresses.length === 0) {
        callback(err ?? new Error(`no address for ${hostname}`), '', 4);
        return;
      }
      if (options.all)
        callback(
          null,
          addresses.map((address) => ({ address, family: 4 }))
        );
      else callback(null, addresses[0], 4);
    });
  };
}
