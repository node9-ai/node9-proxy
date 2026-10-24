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

/**
 * Fields newer than some dashboards. The dashboard validates the snapshot
 * strictly and answers 400 to a field it does not know, which would reject
 * the WHOLE snapshot (config mirror, drift, device info) whenever the proxy
 * is newer than the dashboard. On a 400 the snapshot is sent once more
 * without these (fw#390: `apps` reached the proxy one release before the
 * dashboard that reads it).
 */
export const FIELDS_A_SERVER_MAY_NOT_KNOW = ['apps'] as const;

/** POST the snapshot. Resolves true on a 2xx, false on any failure/timeout. */
export async function shipPolicySnapshot(
  body: PolicySnapshotBody,
  creds: ShipCreds
): Promise<boolean> {
  const url = policySnapshotUrlFrom(creds.apiUrl);
  if (!url) return false;
  const status = await postSnapshot(url, body, creds);
  if (status !== null && status >= 200 && status < 300) return true;
  const newer = FIELDS_A_SERVER_MAY_NOT_KNOW.filter((f) => f in body);
  if (status !== 400 || newer.length === 0) return false;
  const older: PolicySnapshotBody = { ...body };
  for (const f of newer) delete older[f];
  const retry = await postSnapshot(url, older, creds);
  return retry !== null && retry >= 200 && retry < 300;
}

/** One POST; resolves the HTTP status, or null on a network error/timeout. */
function postSnapshot(
  url: string,
  body: PolicySnapshotBody,
  creds: ShipCreds
): Promise<number | null> {
  const payload = JSON.stringify(body);
  const parsed = new URL(url);
  const transport = parsed.protocol === 'http:' ? http : https;

  return new Promise<number | null>((resolve) => {
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
        const status = res.statusCode ?? null;
        res.resume();
        res.on('end', () => resolve(status));
        res.on('error', () => resolve(null));
      }
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.write(payload);
    req.end();
  });
}
