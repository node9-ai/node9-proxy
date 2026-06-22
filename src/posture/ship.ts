// src/posture/ship.ts
// Ships a REDACTED posture snapshot to the SaaS (/intercept/posture/report).
// Mirrors src/daemon/sync.ts pushScanSnapshot: derive the URL from the
// policies/sync base, POST with the Bearer API key, fire-and-forget + timeout.
//
// Redaction (the safety boundary): only score, tier, agent label, the headline
// (risk + action — both generic prose, no values/paths), and per-finding
// { category, severity, title, coverage, what, why, who, fix, owner } leave the
// box. what/why/who are generic plain-language prose; fix is a command or an OS
// action ("bind to 127.0.0.1") — none carry paths. Finding detail[] (which holds
// file paths, MCP server names, ports) is STILL dropped — the only path-bearing
// field never leaves the box.

import http from 'http';
import https from 'https';
import { URL } from 'url';
import type { PostureResult } from './types';

export interface ShipCreds {
  apiKey: string;
  apiUrl: string;
}

/** The redacted wire body. Pure + exported so the redaction is testable. */
export function buildShipBody(result: PostureResult): {
  score: number;
  tier: string;
  agent: string;
  headline: PostureResult['headline'];
  findings: Array<{
    category: string;
    severity: string;
    title: string;
    coverage: string;
    what?: string;
    why?: string;
    who?: string;
    fix?: string;
    owner: string;
    scoreWeight?: number;
    gain?: string;
    cost?: string;
  }>;
} {
  return {
    score: result.score,
    tier: result.tier,
    agent: result.agent,
    headline: result.headline, // { risk, action } | null — both safe strings
    findings: result.findings.map((f) => ({
      category: f.category,
      severity: f.severity,
      title: f.title,
      // Coverage state so the SaaS counts OPEN-only (matching the local score).
      // A non-sensitive enum — no values or paths. Default 'open' if unannotated.
      coverage: f.coverage?.state ?? 'open',
      // Plain-language parity with the CLI report. Prose only, no paths.
      what: f.what,
      why: f.why,
      who: f.who,
      // The runnable fix / OS action — commands + advice, never a path.
      fix: f.fix,
      // Whose job it is. Default 'os' so the SaaS never falsely claims node9 can fix it.
      owner: f.owner ?? 'os',
      // Hardening weight + the flexibility tradeoff (generic prose / a number —
      // no values or paths), so the fleet view can show the same headroom story.
      scoreWeight: f.scoreWeight,
      gain: f.gain,
      cost: f.cost,
    })),
  };
}

/** Derive the posture endpoint from the policies/sync base, or null. */
export function postureUrlFrom(apiUrl: string): string | null {
  return apiUrl.endsWith('/policies/sync')
    ? apiUrl.replace(/\/policies\/sync$/, '/posture/report')
    : null;
}

/**
 * POST the redacted snapshot. Resolves true on a 2xx, false on any failure
 * (bad URL, network error, timeout, non-2xx) — never throws, never blocks the
 * command.
 */
export async function shipPosture(result: PostureResult, creds: ShipCreds): Promise<boolean> {
  const url = postureUrlFrom(creds.apiUrl);
  if (!url) return false;

  const body = JSON.stringify(buildShipBody(result));
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
          'Content-Length': Buffer.byteLength(body),
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
    req.write(body);
    req.end();
  });
}
