// src/audit/index.ts
// Audit-trail helpers: secret redaction + structured log writers.
// These are kept separate from policy logic so they can be called early in
// every hook path (audit writes must happen before config loads — see CLAUDE.md).
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { hashArgs } from './hasher.js';

export const LOCAL_AUDIT_LOG = path.join(os.homedir(), '.node9', 'audit.log');
export const HOOK_DEBUG_LOG = path.join(os.homedir(), '.node9', 'hook-debug.log');

/**
 * Client event id (outbox shipper). Stamped on every audit row at write
 * time; the SaaS batch-ingest endpoint dedups on it, which is what makes
 * shipping idempotent (safe to re-send any batch). Time-prefixed so ids
 * sort roughly chronologically when debugging.
 */
export function generateEventId(): string {
  return `${Date.now().toString(36)}-${crypto.randomBytes(6).toString('hex')}`;
}

const TEST_COMMAND_RE =
  /(?:^|\s)(npm\s+(?:run\s+)?test|npx\s+(?:vitest|jest|mocha)|yarn\s+(?:run\s+)?test|pnpm\s+(?:run\s+)?test|vitest|jest|mocha|pytest|py\.test|cargo\s+test|go\s+test|bundle\s+exec\s+rspec|rspec|phpunit|dotnet\s+test)\b/i;

function isTestCall(toolName: string, args: unknown): boolean {
  if (toolName !== 'Bash' && toolName !== 'bash') return false;
  const cmd = (args as Record<string, unknown> | null)?.command;
  return typeof cmd === 'string' && TEST_COMMAND_RE.test(cmd);
}

export function redactSecrets(text: string): string {
  if (!text) return text;
  let redacted = text;

  // Refined Patterns: Only redact when attached to a known label to avoid masking hashes/paths
  redacted = redacted.replace(
    /(authorization:\s*(?:bearer|basic)\s+)[a-zA-Z0-9._\-\/\\=]+/gi,
    '$1********'
  );
  redacted = redacted.replace(
    /(api[_-]?key|secret|password|token)([:=]\s*['"]?)[a-zA-Z0-9._\-]{8,}/gi,
    '$1$2********'
  );

  return redacted;
}

/**
 * Short, redacted, human-readable preview stored ALONGSIDE argsHash so the
 * dashboard's Action column stays readable in hash mode (the default). The
 * legacy decision-time POST used to send raw redacted args; the shipper
 * ships the local row, so the row itself must carry the display string.
 *
 * Never built for DLP rows — the matched secret may not be covered by
 * redactSecrets' patterns, and dlpSample already carries the safe display.
 */
export function buildArgsPreview(args: unknown): string | undefined {
  try {
    const o = args && typeof args === 'object' ? (args as Record<string, unknown>) : null;
    const primary = o && (o.command ?? o.file_path ?? o.path ?? o.url ?? o.query);
    const text = typeof primary === 'string' ? primary : args ? JSON.stringify(args) : '';
    if (!text) return undefined;
    return redactSecrets(text).slice(0, 120);
  } catch {
    return undefined;
  }
}

export function appendToLog(logPath: string, entry: object): void {
  try {
    const dir = path.dirname(logPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');
  } catch {}
}

export function appendHookDebug(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string; sessionId?: string },
  auditHashArgsEnabled?: boolean
): void {
  const argsField = auditHashArgsEnabled
    ? { argsHash: hashArgs(args) }
    : { args: args ? JSON.parse(redactSecrets(JSON.stringify(args))) : {} };
  appendToLog(HOOK_DEBUG_LOG, {
    ts: new Date().toISOString(),
    tool: toolName,
    ...argsField,
    agent: meta?.agent,
    mcpServer: meta?.mcpServer,
    sessionId: meta?.sessionId,
    hostname: os.hostname(),
    cwd: process.cwd(),
  });
}

export function appendLocalAudit(
  toolName: string,
  args: unknown,
  decision: 'allow' | 'deny',
  checkedBy: string,
  meta?: {
    agent?: string;
    mcpServer?: string;
    sessionId?: string;
    /** Specific smart-rule that fired (e.g.
     *  `shield:project-jail:block-read-ssh`). Optional — included
     *  alongside `checkedBy` (which stays as the generic tag like
     *  `smart-rule-block`) so `[2]` Report can attribute fires to
     *  specific shields without having to redefine the existing
     *  checkedBy taxonomy. */
    ruleName?: string;
    /** Agent-native tool name when canonicalisation rewrote it (e.g.
     *  Hermes `terminal` → canonical `Bash`). Audit row's `tool` field
     *  stays canonical so report aggregation works; this field lets
     *  grep against the name the user actually sees in their agent. */
    agentToolName?: string;
    /** DLP attribution — pattern name + redacted sample. Stored on the
     *  local row so the outbox shipper can carry the finding to the SaaS
     *  (the raw args are redacted/hashed; these two fields are the
     *  signal). */
    dlpPattern?: string;
    dlpSample?: string;
    /** PII attribution — the high-signal PII pattern names that fired
     *  (e.g. "SSN,Credit Card"). The raw args are hashed on PII rows, so
     *  this is the only signal carried; the value itself is never logged. */
    piiPatterns?: string;
    /** SaaS request id when this decision had a pending cloud entry
     *  (/intercept). The BE already holds an origin AuditLog row for that
     *  request; the shipper hands this id over so the BE ENRICHES that row
     *  (sets clientEventId) instead of inserting a duplicate — regardless
     *  of which racer (cloud / native / terminal) decided. */
    cloudRequestId?: string;
  },
  auditHashArgsEnabled?: boolean
): void {
  // NEVER build a preview for DLP rows: the matched secret is in the args
  // and redactSecrets' label-based patterns don't cover every credential
  // shape (a bare AWS key leaked through in testing). Gate on checkedBy —
  // intrinsic to every call site — not just the optional dlpPattern meta.
  const isDlpRow = checkedBy.toLowerCase().includes('dlp') || Boolean(meta?.dlpPattern);
  const preview = auditHashArgsEnabled && !isDlpRow ? buildArgsPreview(args) : undefined;
  const argsField = auditHashArgsEnabled
    ? { argsHash: hashArgs(args), ...(preview ? { argsPreview: preview } : {}) }
    : { args: args ? JSON.parse(redactSecrets(JSON.stringify(args))) : {} };
  const testRun =
    isTestCall(toolName, args) || process.env.NODE9_TESTING === '1' ? { testRun: true } : {};
  const ruleNameField = meta?.ruleName ? { ruleName: meta.ruleName } : {};
  const agentToolNameField = meta?.agentToolName ? { agentToolName: meta.agentToolName } : {};
  const dlpFields = meta?.dlpPattern
    ? { dlpPattern: meta.dlpPattern, dlpSample: meta.dlpSample }
    : {};
  const cloudLinkField = meta?.cloudRequestId ? { cloudRequestId: meta.cloudRequestId } : {};
  appendToLog(LOCAL_AUDIT_LOG, {
    // eid first: the outbox shipper dedups on it, and a fixed leading field
    // makes the JSONL easy to eyeball.
    eid: generateEventId(),
    ts: new Date().toISOString(),
    tool: toolName,
    ...agentToolNameField,
    ...argsField,
    decision,
    checkedBy,
    ...ruleNameField,
    ...dlpFields,
    ...cloudLinkField,
    ...testRun,
    agent: meta?.agent,
    mcpServer: meta?.mcpServer,
    sessionId: meta?.sessionId,
    hostname: os.hostname(),
  });
}

/**
 * Appends a config-change event to the local audit log.
 * Used for security-relevant CLI mutations (e.g. allow overrides) that happen
 * outside the normal tool-call flow and would otherwise be invisible in audit.
 * Intentionally no eid: config events aren't tool calls, and the outbox
 * shipper only ships tool-decision rows (tool + decision + eid).
 */
export function appendConfigAudit(entry: Record<string, unknown>): void {
  appendToLog(LOCAL_AUDIT_LOG, {
    ts: new Date().toISOString(),
    ...entry,
    hostname: os.hostname(),
  });
}
