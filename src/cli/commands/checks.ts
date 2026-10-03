// src/cli/commands/checks.ts
// `node9 checks` — every check in the catalog with the value in force on this
// machine and where that value came from. The catalog is the one list of what
// node9 checks (packages/policy-engine/src/catalog.ts); this command is the
// first thing built from it, before the dashboard screen and the new config
// file. It answers "what is on, and who decided" without the explain
// waterfall.

import type { Command } from 'commander';
import chalk from 'chalk';
import {
  CHECKS,
  CHECK_GROUPS,
  resolveAllChecks,
  type CheckGroup,
  type ResolvedCheck,
} from '@node9/policy-engine';
import { getConfig, catalogSettingsFrom, type Config } from '../../config';
import { configurableValues } from '../../config/v2';

interface ChecksReport {
  policySource: string;
  mode: string;
  packsOn: string[];
  packsOff: string[];
  checks: Array<
    ResolvedCheck & {
      group: CheckGroup;
      title: string;
      pack?: string;
      /** What a config file may set for this check today; empty = fixed. */
      configurable: readonly string[];
    }
  >;
}

export function buildChecksReport(config: Config): ChecksReport {
  const settings = catalogSettingsFrom(config.settings, config.policy);
  // A v2 file states a check explicitly, so its source is known; everything
  // else falls back to "differs from the shipped default".
  const stated = config.policy.checkSources ?? {};
  const resolved = resolveAllChecks(settings).map((r) =>
    r.source === 'locked' ? r : stated[r.id] ? { ...r, source: stated[r.id] } : r
  );
  const packs = [...new Set(CHECKS.filter((c) => c.pack).map((c) => c.pack!))].sort();
  const on = new Set(settings.appliedShields ?? []);
  return {
    policySource: config.policySource ?? 'local',
    mode: config.settings.mode,
    packsOn: packs.filter((p) => on.has(p)),
    packsOff: packs.filter((p) => !on.has(p)),
    checks: resolved.map((r, i) => ({
      ...r,
      group: CHECKS[i].group,
      title: CHECKS[i].title,
      ...(CHECKS[i].pack && { pack: CHECKS[i].pack }),
      configurable: configurableValues(CHECKS[i].id),
    })),
  };
}

const VALUE_COLOR: Record<string, (s: string) => string> = {
  off: chalk.gray,
  log: chalk.blue,
  review: chalk.yellow,
  block: chalk.red,
};

function renderChecks(report: ChecksReport): string {
  const lines: string[] = [];
  const where =
    report.policySource === 'workspace'
      ? 'workspace (app.node9.ai)'
      : 'local (~/.node9/config.json)';
  lines.push('');
  lines.push(`${chalk.cyan.bold('node9 checks')}   policy: ${where}   mode: ${report.mode}`);
  lines.push('');

  const row = (c: ChecksReport['checks'][number]) => {
    const value = (VALUE_COLOR[c.value] ?? chalk.white)(c.value.padEnd(7));
    const source = c.source === 'locked' ? chalk.magenta('locked') : chalk.gray(c.source);
    const fixed =
      c.source !== 'locked' && c.configurable.length === 0
        ? chalk.gray('  (not configurable yet)')
        : '';
    return `  ${c.id.padEnd(34)} ${value} ${source.padEnd(20)} ${c.title}${fixed}`;
  };

  for (const group of CHECK_GROUPS) {
    const rows = report.checks.filter((c) => c.group === group.id && !c.pack);
    if (rows.length === 0) continue;
    lines.push(chalk.bold(group.title));
    for (const c of rows) lines.push(row(c));
    lines.push('');
  }

  for (const pack of report.packsOn) {
    lines.push(chalk.bold(`Pack: ${pack}`));
    for (const c of report.checks.filter((c) => c.pack === pack)) lines.push(row(c));
    lines.push('');
  }
  if (report.packsOff.length > 0) {
    lines.push(chalk.gray(`Packs off: ${report.packsOff.join(', ')}`));
    lines.push('');
  }
  return lines.join('\n');
}

export function registerChecksCommand(program: Command): void {
  program
    .command('checks')
    .description('List every check with the value in force on this machine and its source')
    .option('--json', 'Machine-readable output')
    .action((opts: { json?: boolean }) => {
      const report = buildChecksReport(getConfig());
      if (opts.json) {
        console.log(JSON.stringify(report, null, 2));
        return;
      }
      console.log(renderChecks(report));
    });
}
