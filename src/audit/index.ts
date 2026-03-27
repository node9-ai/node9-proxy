// src/audit/index.ts
// Audit-trail helpers: secret redaction + structured log writers.
// These are kept separate from policy logic so they can be called early in
// every hook path (audit writes must happen before config loads — see CLAUDE.md).
import fs from 'fs';
import path from 'path';
import os from 'os';

export const LOCAL_AUDIT_LOG = path.join(os.homedir(), '.node9', 'audit.log');
export const HOOK_DEBUG_LOG = path.join(os.homedir(), '.node9', 'hook-debug.log');

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
  meta?: { agent?: string; mcpServer?: string }
): void {
  const safeArgs = args ? JSON.parse(redactSecrets(JSON.stringify(args))) : {};
  appendToLog(HOOK_DEBUG_LOG, {
    ts: new Date().toISOString(),
    tool: toolName,
    args: safeArgs,
    agent: meta?.agent,
    mcpServer: meta?.mcpServer,
    hostname: os.hostname(),
    cwd: process.cwd(),
  });
}

export function appendLocalAudit(
  toolName: string,
  args: unknown,
  decision: 'allow' | 'deny',
  checkedBy: string,
  meta?: { agent?: string; mcpServer?: string }
): void {
  const safeArgs = args ? JSON.parse(redactSecrets(JSON.stringify(args))) : {};
  appendToLog(LOCAL_AUDIT_LOG, {
    ts: new Date().toISOString(),
    tool: toolName,
    args: safeArgs,
    decision,
    checkedBy,
    agent: meta?.agent,
    mcpServer: meta?.mcpServer,
    hostname: os.hostname(),
  });
}

/**
 * Appends a config-change event to the local audit log.
 * Used for security-relevant CLI mutations (e.g. allow overrides) that happen
 * outside the normal tool-call flow and would otherwise be invisible in audit.
 */
export function appendConfigAudit(entry: Record<string, unknown>): void {
  appendToLog(LOCAL_AUDIT_LOG, {
    ts: new Date().toISOString(),
    ...entry,
    hostname: os.hostname(),
  });
}
