// src/apps/report.ts
// The "Apps" lines of `node9 report` (node9Firewall#390, phase 2): what node9
// found and whether it is protected, and, at the one moment it helps, the
// dashboard: a machine that is not logged in and was asked 10 or more times
// in the period. Pure: returns lines, the caller prints.
import { APP_CATALOG } from './catalog';
import type { AppsFile } from './state';

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
