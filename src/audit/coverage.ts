// Phase 3b of the report-correctness verification roadmap
// (doc/roadmap/report-correctness-verification.md).
//
// Pure helper: compute audit-log coverage against the hook-debug log.
//
// The hook-debug log records errors that were caught in hook code paths
// (the CLAUDE.md "Always write to hook-debug.log" rule). If a session
// produced hook-debug entries but no corresponding audit.log entries, the
// hook may have failed before reaching the audit-write call — a potential
// gap. This helper surfaces those mismatches; rendering / CLI wiring is
// deferred to a follow-on doctor subcommand.
//
// Format notes:
// - audit.log is one JSON object per line. Reliable to parse.
// - hook-debug.log is sometimes JSON, sometimes plain text (e.g.
//   `JSON_PARSE_ERROR: ...`). Each line is best-effort: parsed as JSON
//   when possible, otherwise counted as a generic error without session
//   attribution.

import fs from 'fs';

export interface AuditCoverageReport {
  /** Total parseable audit.log lines (one JSON object each). */
  auditEntries: number;
  /** Total non-empty hook-debug.log lines (any format). */
  hookDebugEntries: number;
  /** Unique session_ids observed in audit.log. */
  sessionIdsWithAudit: Set<string>;
  /** Unique session_ids observed in JSON-parseable hook-debug.log lines. */
  sessionIdsWithDebug: Set<string>;
  /** Sessions seen in hook-debug.log but not audit.log — potential gaps. */
  sessionsWithDebugMissingAudit: string[];
  /** True iff the audit-log file exists. */
  hasAuditFile: boolean;
  /** True iff the hook-debug-log file exists. */
  hasDebugFile: boolean;
}

function readLines(filePath: string): string[] {
  if (!fs.existsSync(filePath)) return [];
  try {
    return fs
      .readFileSync(filePath, 'utf-8')
      .split('\n')
      .filter((l) => l.length > 0);
  } catch {
    return [];
  }
}

function extractSessionId(line: string): string | null {
  try {
    const parsed = JSON.parse(line) as Record<string, unknown>;
    const sid = parsed.sessionId;
    return typeof sid === 'string' && sid.length > 0 ? sid : null;
  } catch {
    return null;
  }
}

export function computeAuditCoverage(
  auditLogPath: string,
  hookDebugLogPath: string
): AuditCoverageReport {
  const hasAuditFile = fs.existsSync(auditLogPath);
  const hasDebugFile = fs.existsSync(hookDebugLogPath);

  const auditLines = readLines(auditLogPath);
  const debugLines = readLines(hookDebugLogPath);

  const sessionIdsWithAudit = new Set<string>();
  for (const line of auditLines) {
    const sid = extractSessionId(line);
    if (sid) sessionIdsWithAudit.add(sid);
  }

  const sessionIdsWithDebug = new Set<string>();
  for (const line of debugLines) {
    const sid = extractSessionId(line);
    if (sid) sessionIdsWithDebug.add(sid);
  }

  const sessionsWithDebugMissingAudit = [...sessionIdsWithDebug]
    .filter((s) => !sessionIdsWithAudit.has(s))
    .sort();

  return {
    auditEntries: auditLines.length,
    hookDebugEntries: debugLines.length,
    sessionIdsWithAudit,
    sessionIdsWithDebug,
    sessionsWithDebugMissingAudit,
    hasAuditFile,
    hasDebugFile,
  };
}
