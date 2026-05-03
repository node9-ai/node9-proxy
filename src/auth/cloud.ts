// src/auth/cloud.ts
// Node9 SaaS cloud channel: handshake, polling, resolution, and local-allow audit reporting.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { type RiskMetadata } from '../context-sniper';
import { HOOK_DEBUG_LOG } from '../audit';

export interface CloudApprovalResult {
  approved: boolean;
  reason?: string;
  remoteApprovalOnly?: boolean;
}

// Cap on the DLP redacted sample length forwarded to the SaaS — defends
// against partially-redacted secret material being persisted in audit logs
// when upstream redaction is incomplete.
const DLP_SAMPLE_MAX_LEN = 200;
const DLP_PATTERN_MAX_LEN = 100;

// Known checkedBy values emitted by the orchestrator. Anything outside this
// set is normalized to 'unknown' before transmission — defends against log
// injection and prevents free-form caller strings from polluting the audit
// stream (e.g. JSON-shaped values that confuse downstream log consumers).
const KNOWN_CHECKED_BY = new Set([
  'dlp-block',
  'observe-mode-dlp-would-block',
  'dlp-review-flagged',
  'loop-detected',
  'audit-mode',
  'local-policy',
  'smart-rule-block',
  'persistent',
  'trust',
  'observe-mode',
  'observe-mode-would-block',
]);

/**
 * Validates the audit URL before we send the bearer token to it.
 *
 * Threat model: `creds.apiUrl` originates from `$NODE9_API_URL` or
 * `~/.node9/credentials.json`. Both are local-user-controlled but a
 * supply-chain compromise, malicious installer, or env-var injection from a
 * parent process could redirect audit traffic — including the API key in the
 * Authorization header — to an attacker-controlled host. We require HTTPS,
 * with a narrow exception for loopback addresses used by tests/dev fixtures.
 *
 * Returns the parsed URL on success, or null when the URL is malformed,
 * uses a non-HTTPS scheme on a non-loopback host, or contains userinfo.
 */
function validateApiUrl(raw: string): URL | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  // Reject userinfo (`https://attacker@real.host`) — the Bearer token is
  // already in the Authorization header; userinfo here is always a smell.
  if (u.username || u.password) return null;
  if (u.protocol === 'https:') return u;
  if (u.protocol === 'http:') {
    const h = u.hostname;
    if (h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '[::1]') return u;
  }
  return null;
}

/**
 * Send an audit record to the SaaS backend for a locally fast-pathed call.
 * Returns a Promise so callers that precede process.exit(0) can await it.
 * Failures are silently ignored — never blocks the agent.
 *
 * `containsSensitiveArgs` is the explicit security decision controlled by
 * the call site: when true, raw args are stripped before transmission.
 * The previous substring-match-on-checkedBy heuristic was fragile because
 * it both (a) trusted a free-form caller-controlled string for a security
 * decision and (b) silently sent raw args for any code path whose tag
 * happened not to contain "dlp" (e.g. loop-detected following a DLP match).
 */
export function auditLocalAllow(
  toolName: string,
  args: unknown,
  checkedBy: string,
  creds: { apiKey: string; apiUrl: string },
  meta?: { agent?: string; mcpServer?: string },
  dlpInfo?: { pattern: string; redactedSample: string },
  containsSensitiveArgs: boolean = false,
  // Optional rule attribution. Forwarded into the audit-log row's
  // riskMetadata column so the SaaS /report endpoint can classify the
  // event by rule name (engine's classifyAuditEntry uses ruleName as
  // the highest-priority signal). Without this, every local
  // smart-rule-block falls back to "high — Bash block" in the Report.
  riskMetadata?: {
    ruleName?: string;
    ruleDescription?: string;
    blockedByLabel?: string;
    matchedField?: string;
    matchedWord?: string;
  }
): Promise<void> {
  // SSRF / key-leak guard: refuse to send the bearer token to anything that
  // isn't HTTPS (loopback excepted for tests/dev). Silent skip — we never
  // want the audit path to break the agent.
  const validated = validateApiUrl(creds.apiUrl);
  if (!validated) {
    try {
      fs.appendFileSync(
        HOOK_DEBUG_LOG,
        `[audit] refused to send: invalid apiUrl scheme/host (got "${String(creds.apiUrl).slice(0, 200)}")\n`
      );
    } catch {}
    return Promise.resolve();
  }

  const safeArgs = containsSensitiveArgs ? { tool: toolName, redacted: true } : args;
  const dlpSample =
    dlpInfo && typeof dlpInfo.redactedSample === 'string'
      ? dlpInfo.redactedSample.slice(0, DLP_SAMPLE_MAX_LEN)
      : undefined;
  const dlpPattern =
    dlpInfo && typeof dlpInfo.pattern === 'string'
      ? dlpInfo.pattern.slice(0, DLP_PATTERN_MAX_LEN)
      : undefined;
  const safeCheckedBy = KNOWN_CHECKED_BY.has(checkedBy) ? checkedBy : 'unknown';

  // Strip empty / undefined fields so the backend Zod schema (.strict())
  // doesn't reject the payload. Only forward keys that have a real value.
  const cleanedRiskMetadata = riskMetadata
    ? Object.fromEntries(
        Object.entries(riskMetadata).filter(([, v]) => typeof v === 'string' && v.length > 0)
      )
    : undefined;
  const hasRiskMetadata = cleanedRiskMetadata && Object.keys(cleanedRiskMetadata).length > 0;

  return fetch(`${validated.toString().replace(/\/$/, '')}/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${creds.apiKey}` },
    body: JSON.stringify({
      toolName,
      args: safeArgs,
      checkedBy: safeCheckedBy,
      ...(dlpInfo && { dlpPattern, dlpSample }),
      ...(hasRiskMetadata && { riskMetadata: cleanedRiskMetadata }),
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
  riskMetadata?: RiskMetadata,
  agentPolicy?: 'require_approval' | 'block_on_rules',
  forceReview?: boolean
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

  if (!creds.apiKey) throw new Error('Node9 API Key is missing');

  // Read CI context written by the agent before the git push gate
  let ciContext: Record<string, unknown> | undefined;
  if (process.env.CI) {
    try {
      const ciContextPath = path.join(os.homedir(), '.node9', 'ci-context.json');
      const stats = fs.statSync(ciContextPath);
      if (stats.size > 10_000) throw new Error('ci-context.json exceeds 10 KB');
      const raw = fs.readFileSync(ciContextPath, 'utf8');
      const parsed = JSON.parse(raw) as unknown;
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('ci-context.json is not a plain object');
      }
      // Allowlist: only forward known safe keys — never tokens or credentials
      const p = parsed as Record<string, unknown>;
      ciContext = {
        tests_after: p['tests_after'],
        files_changed: p['files_changed'],
        issues_found: p['issues_found'],
        issues_fixed: p['issues_fixed'],
        github_repository: p['github_repository'],
        github_head_ref: p['github_head_ref'],
        iteration: p['iteration'],
        draft_pr_number: p['draft_pr_number'],
        draft_pr_url: p['draft_pr_url'],
      };
    } catch {
      // not present — not a CI push gate
    }
  }

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
        ...(ciContext && { ciContext }),
        ...(agentPolicy && { policy: agentPolicy }),
        ...(forceReview && { forceReview: true }),
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

      const statusBody = (await statusRes.json()) as {
        status: string;
        reason?: string;
        feedbackText?: string;
      };
      const { status } = statusBody;

      if (status === 'APPROVED') {
        return { approved: true, reason: statusBody.reason };
      }
      if (status === 'DENIED' || status === 'AUTO_BLOCKED' || status === 'TIMED_OUT') {
        return { approved: false, reason: statusBody.reason };
      }
      if (status === 'FIX') {
        const feedbackText =
          statusBody.feedbackText ?? statusBody.reason ?? 'Run again with feedback.';
        return { approved: false, reason: feedbackText };
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
