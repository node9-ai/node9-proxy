// src/posture/render.ts
// Doctor-style chalk rendering of a PostureResult — the shareable scorecard.

import chalk from 'chalk';
import type { Finding, PostureResult, Severity } from './types';

const ICON: Record<Severity, string> = {
  critical: chalk.red('❌'),
  high: chalk.red('❌'),
  medium: chalk.yellow('⚠️ '),
  advisory: chalk.gray('⚠️ '),
};

const TIER_LABEL: Record<PostureResult['tier'], string> = {
  good: chalk.green('Good'),
  'at-risk': chalk.yellow('At risk'),
  critical: chalk.red('Critical'),
};

/** Pad a category label to a fixed column so detail lines align. */
const LABEL_WIDTH = 14;
function label(category: string): string {
  // Pad to the column, but always leave ≥1 space so a category wider than the
  // column (e.g. 'Network exposure') doesn't butt up against the title.
  return chalk.bold(category.padEnd(Math.max(LABEL_WIDTH, category.length + 1)));
}

function renderFinding(f: Finding): string[] {
  const lines: string[] = [];
  lines.push(`  ${ICON[f.severity]} ${label(f.category)}${f.title}`);
  const indent = ' '.repeat(2 + 3 + LABEL_WIDTH);
  for (const d of f.detail) lines.push(indent + chalk.gray(d));
  if (f.fix) lines.push(indent + chalk.cyan('→ ' + f.fix));
  return lines;
}

export function renderPosture(result: PostureResult): string {
  const lines: string[] = [];
  const tier = TIER_LABEL[result.tier];
  lines.push('');
  lines.push(
    chalk.cyan.bold(`🛡️  Node9 Posture`) +
      chalk.gray(` — ${result.agent}`) +
      `        ${chalk.bold(`Score: ${result.score}/100`)}  (${tier})`
  );
  lines.push('');

  for (const f of result.findings) {
    lines.push(...renderFinding(f));
  }
  for (const cat of result.passedCategories) {
    lines.push(`  ${chalk.green('✅')} ${label(cat)}${chalk.gray('no issues found')}`);
  }

  lines.push('');
  const crit = result.findings.filter((f) => f.severity === 'critical').length;
  const high = result.findings.filter((f) => f.severity === 'high').length;
  const med = result.findings.filter((f) => f.severity === 'medium').length;
  const adv = result.findings.filter((f) => f.severity === 'advisory').length;
  const parts: string[] = [];
  if (crit) parts.push(chalk.red(`${crit} critical`));
  if (high) parts.push(chalk.red(`${high} high`));
  if (med) parts.push(chalk.yellow(`${med} medium`));
  if (adv) parts.push(chalk.gray(`${adv} advisory`));
  const summary = parts.length ? parts.join(' · ') : chalk.green('no findings');
  lines.push(`  ${summary}  ·  ${chalk.gray('track your fleet at app.node9.ai/posture')}`);
  lines.push('');
  return lines.join('\n');
}
