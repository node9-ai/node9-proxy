// src/apps/report.ts
// The "Apps" lines of `node9 report` (node9Firewall#390, phase 2): what node9
// found and whether it is protected, and, at the one moment it helps, the
// dashboard: a machine that is not logged in and was asked 10 or more times
// in the period. Pure: returns lines, the caller prints.
import fs from 'fs';
import { APP_CATALOG, actionWordOf } from './catalog';
import type { AppsFile } from './state';
import { suggestFromApprovals, type ApprovalRow, type Suggestion } from '@node9/policy-engine';

export const DASHBOARD_NUDGE_AT = 10;

export function appsReportLines(
  file: AppsFile,
  activeShields: readonly string[],
  opts: { loggedIn: boolean; asked: number }
): string[] {
  const active = new Set(activeShields);
  const apps = APP_CATALOG.filter((a) => file.apps[a.slug] || active.has(a.shield));
  const lines: string[] = [];
  if (apps.length > 0) {
    const on = apps.filter((a) => active.has(a.shield)).map((a) => a.label);
    const off = apps.filter((a) => !active.has(a.shield)).map((a) => a.label);
    if (on.length > 0) lines.push(`Apps protected: ${on.join(', ')}`);
    if (off.length > 0) lines.push(`Apps you turned off: ${off.join(', ')}`);
    lines.push('See how each was found, or turn one off: node9 apps');
  }
  if (!opts.loggedIn && opts.asked >= DASHBOARD_NUDGE_AT) {
    lines.push(
      `node9 asked ${opts.asked} times this period. Approve from your phone and stop a question with one click: node9 login`
    );
  }
  return lines;
}

const AUDIT_TAIL_BYTES = 5 * 1024 * 1024;

function readTail(file: string): string {
  let fd: number | undefined;
  try {
    fd = fs.openSync(file, 'r');
    const size = fs.fstatSync(fd).size;
    const start = Math.max(0, size - AUDIT_TAIL_BYTES);
    const buf = Buffer.alloc(size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    const text = buf.toString('utf8');
    return start > 0 ? text.slice(text.indexOf('\n') + 1) : text;
  } catch {
    return '';
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/**
 * A person's decisions in the audit log since `sinceMs` (fw#390, phase 4):
 * an inline approval in the agent's own prompt (`checkedBy: inline-review`),
 * and a card a person answered (`decidedBy: person`), approved or denied.
 * A denial in the agent's prompt leaves no row and cannot be counted.
 */
export function approvalsFromAudit(auditFile: string, sinceMs: number): ApprovalRow[] {
  const out: ApprovalRow[] = [];
  for (const line of readTail(auditFile).split('\n')) {
    if (!line.startsWith('{')) continue;
    let row: Record<string, unknown>;
    try {
      row = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    const ts = typeof row.ts === 'string' ? Date.parse(row.ts) : NaN;
    if (!(ts >= sinceMs)) continue;
    const ruleName = typeof row.ruleName === 'string' ? row.ruleName : '';
    if (!ruleName) continue;
    const inline = row.checkedBy === 'inline-review' && row.decision === 'allow';
    const person = row.decidedBy === 'person';
    if (!inline && !person) continue;
    const allowed = row.decision === 'allow' || row.decision === 'allowed';
    const tool = typeof row.tool === 'string' ? row.tool : '';
    const ns = /^mcp__([^_](?:[^_]|_(?!_))*?)__/i.exec(tool);
    const server = ns?.[1] ?? (typeof row.mcpServer === 'string' ? row.mcpServer : undefined);
    out.push({
      ruleName,
      decision: inline || allowed ? 'approved' : 'denied',
      ...(typeof row.sessionId === 'string' ? { sessionId: row.sessionId } : {}),
      ...(server ? { server } : {}),
    });
  }
  return out;
}

/** The command that applies a suggestion, for a person to run. */
export function suggestionLine(s: Suggestion): string {
  if (s.kind === 'quiet-rule') {
    const app = APP_CATALOG.find((a) => a.shield === s.shield);
    const word = actionWordOf(s.shield, s.rule);
    const what = word ?? s.rule.replace(/^review-/, '');
    const cmd = word
      ? `node9 apps ${app?.slug ?? s.shield} ${word} allow --force`
      : `node9 shield set ${s.shield} ${s.rule} allow --force`;
    return `${app?.label ?? s.shield}: you approved ${what} ${s.approvals} times in ${s.sessions} sessions. Stop asking: ${cmd}`;
  }
  return `Server ${s.server} was asked about ${s.approvals} times and you approved each. Which app is it? node9 apps link ${s.server} <app>`;
}

/** The suggestion lines of `node9 report`. */
export function suggestionLines(rows: readonly ApprovalRow[]): string[] {
  return suggestFromApprovals(rows).slice(0, 5).map(suggestionLine);
}
