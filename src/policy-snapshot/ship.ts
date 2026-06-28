// src/policy-snapshot/ship.ts
// POST the effective-policy snapshot to the SaaS (/intercept/policy/snapshot).
// Mirrors src/posture/ship.ts: derive the URL from the policies/sync base, POST
// with the Bearer API key, fire-and-forget + timeout. Returns true on 2xx.

import http from 'http';
import https from 'https';
import { URL } from 'url';
import type { PolicySnapshotBody } from './build.js';

export interface ShipCreds {
  apiKey: string;
  apiUrl: string;
}

export function policySnapshotUrlFrom(apiUrl: string): string | null {
  return apiUrl.endsWith('/policies/sync')
    ? apiUrl.replace(/\/policies\/sync$/, '/policy/snapshot')
    : null;
}

/** POST the snapshot. Resolves true on a 2xx, false on any failure/timeout. */
export async function shipPolicySnapshot(
  body: PolicySnapshotBody,
  creds: ShipCreds
): Promise<boolean> {
  const url = policySnapshotUrlFrom(creds.apiUrl);
  if (!url) return false;

  const payload = JSON.stringify(body);
  const parsed = new URL(url);
  const transport = parsed.protocol === 'http:' ? http : https;

  return new Promise<boolean>((resolve) => {
    const req = transport.request(
      {
        hostname: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port, 10) : undefined,
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          Authorization: `Bearer ${creds.apiKey}`,
        },
        timeout: 10_000,
      },
      (res) => {
        const ok = !!res.statusCode && res.statusCode >= 200 && res.statusCode < 300;
        res.resume();
        res.on('end', () => resolve(ok));
        res.on('error', () => resolve(false));
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.write(payload);
    req.end();
  });
}
