// src/auth/cloud.ts
// Node9 SaaS cloud channel: handshake, polling, resolution, and local-allow audit reporting.
import fs from 'fs';
import os from 'os';
import { type RiskMetadata } from '../context-sniper';
import { HOOK_DEBUG_LOG } from '../audit';

export interface CloudApprovalResult {
  approved: boolean;
  reason?: string;
  remoteApprovalOnly?: boolean;
}

/**
 * Send an audit record to the SaaS backend for a locally fast-pathed call.
 * Returns a Promise so callers that precede process.exit(0) can await it.
 * Failures are silently ignored — never blocks the agent.
 */
export function auditLocalAllow(
  toolName: string,
  args: unknown,
  checkedBy: string,
  creds: { apiKey: string; apiUrl: string },
  meta?: { agent?: string; mcpServer?: string }
): Promise<void> {
  return fetch(`${creds.apiUrl}/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${creds.apiKey}` },
    body: JSON.stringify({
      toolName,
      args,
      checkedBy,
      context: {
        agent: meta?.agent,
        mcpServer: meta?.mcpServer,
        hostname: os.hostname(),
        cwd: process.cwd(),
        platform: os.platform(),
      },
    }),
    signal: AbortSignal.timeout(5000),
  })
    .then(() => {})
    .catch(() => {});
}

/**
 * STEP 1: The Handshake. Runs BEFORE the local UI is spawned to check for locks.
 */
export async function initNode9SaaS(
  toolName: string,
  args: unknown,
  creds: { apiKey: string; apiUrl: string },
  meta?: { agent?: string; mcpServer?: string },
  riskMetadata?: RiskMetadata
): Promise<{
  pending: boolean;
  requestId?: string;
  approved?: boolean;
  reason?: string;
  remoteApprovalOnly?: boolean;
  shadowMode?: boolean;
  shadowReason?: string;
}> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(creds.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${creds.apiKey}` },
      body: JSON.stringify({
        toolName,
        args,
        context: {
          agent: meta?.agent,
          mcpServer: meta?.mcpServer,
          hostname: os.hostname(),
          cwd: process.cwd(),
          platform: os.platform(),
        },
        ...(riskMetadata && { riskMetadata }),
      }),
      signal: controller.signal,
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    return (await response.json()) as {
      pending: boolean;
      requestId?: string;
      approved?: boolean;
      reason?: string;
      remoteApprovalOnly?: boolean;
      shadowMode?: boolean;
      shadowReason?: string;
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * STEP 2: The Poller. Runs INSIDE the Race Engine.
 */
export async function pollNode9SaaS(
  requestId: string,
  creds: { apiKey: string; apiUrl: string },
  signal: AbortSignal
): Promise<CloudApprovalResult> {
  const statusUrl = `${creds.apiUrl}/status/${requestId}`;
  const POLL_INTERVAL_MS = 1000;
  const POLL_DEADLINE = Date.now() + 10 * 60 * 1000;

  while (Date.now() < POLL_DEADLINE) {
    if (signal.aborted) throw new Error('Aborted');
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));

    try {
      const pollCtrl = new AbortController();
      const pollTimer = setTimeout(() => pollCtrl.abort(), 5000);
      const statusRes = await fetch(statusUrl, {
        headers: { Authorization: `Bearer ${creds.apiKey}` },
        signal: pollCtrl.signal,
      });
      clearTimeout(pollTimer);

      if (!statusRes.ok) continue;

      const { status, reason } = (await statusRes.json()) as { status: string; reason?: string };

      if (status === 'APPROVED') {
        return { approved: true, reason };
      }
      if (status === 'DENIED' || status === 'AUTO_BLOCKED' || status === 'TIMED_OUT') {
        return { approved: false, reason };
      }
    } catch {
      /* transient network error */
    }
  }
  return { approved: false, reason: 'Cloud approval timed out after 10 minutes.' };
}

/**
 * Reports a locally-made decision (native/browser/terminal) back to the SaaS
 * so the pending request doesn't stay stuck in Mission Control.
 */
export async function resolveNode9SaaS(
  requestId: string,
  creds: { apiKey: string; apiUrl: string },
  approved: boolean,
  decidedBy?: string
): Promise<void> {
  try {
    const resolveUrl = `${creds.apiUrl}/requests/${requestId}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const res = await fetch(resolveUrl, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${creds.apiKey}` },
      body: JSON.stringify({
        decision: approved ? 'APPROVED' : 'DENIED',
        ...(decidedBy && { decidedBy }),
      }),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      fs.appendFileSync(
        HOOK_DEBUG_LOG,
        `[resolve-cloud] PATCH ${resolveUrl} → HTTP ${res.status}\n`
      );
    }
  } catch (err) {
    fs.appendFileSync(
      HOOK_DEBUG_LOG,
      `[resolve-cloud] PATCH failed for ${requestId}: ${(err as Error).message}\n`
    );
  }
}
