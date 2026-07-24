// src/posture/render.ts
// Doctor-style chalk rendering of a PostureResult — the shareable scorecard.

import chalk from 'chalk';
import type { Finding, PostureResult, Severity } from './types';
import { openHeadroom } from './score';

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

/** Greedy word-wrap for the headline narrative (plain text, no ANSI). */
function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  let cur = '';
  for (const word of text.split(' ')) {
    if (cur && (cur + ' ' + word).length > width) {
      out.push(cur);
      cur = word;
    } else {
      cur = cur ? cur + ' ' + word : word;
    }
  }
  if (cur) out.push(cur);
  return out;
}

/** Pad a category label to a fixed column so detail lines align. */
const LABEL_WIDTH = 14;
function label(category: string): string {
  // Pad to the column, but always leave ≥1 space so a category wider than the
  // column (e.g. 'Network exposure') doesn't butt up against the title.
  return chalk.bold(category.padEnd(Math.max(LABEL_WIDTH, category.length + 1)));
}

/** What a covered row is guarding, from the finding's own detail — data-first,
 *  first entry + a count (the P1 cap rule). 'this' when it has no specifics. */
function guardedWhat(f: Finding): string {
  if (f.detail.length === 0) return 'this';
  const reads = f.coverageProbe?.kind === 'fileRead' ? 'reads of ' : '';
  const more = f.detail.length > 1 ? ` and ${f.detail.length - 1} more` : '';
  return `${reads}${f.detail[0]}${more}`;
}

function renderFinding(
  f: Finding,
  showWeight = false,
  displayLabel: string = f.category
): string[] {
  const lines: string[] = [];
  // In the AVAILABLE tier, lead with the score gain (+N) so the value of turning
  // the layer on is the first thing read.
  const wt = showWeight && f.scoreWeight ? chalk.cyan.bold(`+${f.scoreWeight} `) : '';
  lines.push(`  ${ICON[f.severity]} ${label(displayLabel)}${wt}${f.title}`);
  const indent = ' '.repeat(2 + 3 + LABEL_WIDTH);
  // Plain-language explanation first (what / why / who), wrapped so that
  // indent + text stays under ~80 columns.
  const width = 80 - indent.length;
  for (const s of [f.what, f.why, f.who]) {
    if (s) for (const l of wrap(s, width)) lines.push(indent + chalk.gray(l));
  }
  // Then hard specifics (file lists, ports) — kept on one line each — then the
  // fix prose, wrapped with its continuation aligned under the text.
  for (const d of f.detail) lines.push(indent + chalk.gray(d));
  if (f.fix) {
    // Preserve intentional line breaks (the fix may carry a bulleted option
    // list); wrap each segment, and only the first physical line gets the arrow.
    let first = true;
    for (const seg of f.fix.split('\n')) {
      for (const l of wrap(seg, width - 2)) {
        lines.push(indent + chalk.cyan(first ? '→ ' + l : '  ' + l));
        first = false;
      }
    }
  }
  // The security↔flexibility tradeoff, made explicit on both axes. Only the
  // first wrapped line carries the label; continuations align under the text.
  const tradeoff: Array<[string | undefined, string, (s: string) => string]> = [
    [f.gain, 'gain: ', chalk.green],
    [f.cost, 'cost: ', chalk.yellow],
  ];
  for (const [text, lbl, color] of tradeoff) {
    if (!text) continue;
    wrap(text, width - 6).forEach((l, i) => {
      lines.push(indent + (i === 0 ? color(lbl) : '      ') + chalk.gray(l));
    });
  }
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
  // The headroom line: a sub-100 score isn't a failure — it's hardening you
  // can choose to turn on. When genuine exposures are ALSO open, name both
  // buckets — otherwise the reader computes score+headroom≠100 and mistrusts
  // the number. Advisories never deduct (score.ts), so they don't count as
  // the "rest".
  const headroom = openHeadroom(result.findings);
  if (headroom > 0) {
    const openExposures = result.findings.filter(
      (f) =>
        f.coverage?.state !== 'covered' &&
        f.coverage?.state !== 'cant-fix' &&
        !f.scoreWeight &&
        f.severity !== 'advisory'
    ).length;
    const note =
      openExposures > 0
        ? `Of the gap to 100: ${headroom} pts is optional hardening you can choose ` +
          'to turn on (the 🔒 tier below, each at some cost to flexibility); the ' +
          'rest is the open findings — the flagged rows below. Fix those first.'
        : `${headroom} pts of headroom — optional hardening you can choose to ` +
          'turn on (the 🔒 tier below), each at some cost to flexibility.';
    for (const l of wrap(note, 76)) lines.push('  ' + chalk.gray(l));
  }
  lines.push('');

  if (result.headline) {
    const indent = '     ';
    lines.push(`  ${chalk.red.bold('🔥 Biggest risk')}`);
    for (const l of wrap(result.headline.risk, 74)) lines.push(indent + chalk.white(l));
    const action = wrap(`Do this first: ${result.headline.action}`, 72);
    action.forEach((l, i) => lines.push(indent + chalk.cyan(i === 0 ? '→ ' + l : '  ' + l)));
    lines.push('');
  }

  // 🟢 What node9 is already enforcing — shown first as reassurance, never as
  // a risk. (Covered findings are excluded from the open-findings render below.)
  const covered = result.findings.filter((f) => f.coverage?.state === 'covered');
  const open = result.findings.filter((f) => f.coverage?.state !== 'covered');
  // A category present in BOTH lists reads as a contradiction (✅ Secrets six
  // lines above ❌ Secrets) — qualify the labels ONLY then; a category on one
  // side keeps its bare name.
  const collision = new Set(
    covered.map((f) => f.category).filter((c) => open.some((o) => o.category === c))
  );
  const openLabel = (f: Finding) =>
    collision.has(f.category) ? `${f.category} (exposed)` : f.category;
  if (covered.length > 0) {
    lines.push('  ' + chalk.green('🟢 ON NOW — node9 is enforcing these (your floor)'));
    for (const f of covered) {
      const gated = f.coverage?.level === 'review' ? 'approval-gating' : 'blocking';
      const via = f.coverage?.via ?? 'node9';
      const lbl = collision.has(f.category) ? `${f.category} (guarded)` : f.category;
      lines.push(
        `  ${chalk.green('✅')} ${label(lbl)}${chalk.gray(`${via} is ${gated} ${guardedWhat(f)}`)}`
      );
    }
    lines.push('');
  }

  // Group OPEN findings by WHOSE JOB it is: node9 has a lever (run a command),
  // vs only-you (OS/infra — node9 can detect but not fix). Unset owner → 'os'
  // (don't falsely claim node9 can fix it).
  const node9Open = open.filter((f) => f.owner === 'node9');
  // 🔒 middle tier: owner is still the user's, but node9 has an adjacent lever
  // that reduces the risk (a runnable command). Sits between fix-it and only-you.
  const reduceOpen = open.filter((f) => f.owner !== 'node9' && f.node9Reduces);
  const osOpen = open.filter((f) => f.owner !== 'node9' && !f.node9Reduces);

  if (node9Open.length > 0) {
    lines.push('  ' + chalk.cyan.bold('🔧 node9 can fix these — run the command'));
    for (const f of node9Open) lines.push(...renderFinding(f, true, openLabel(f)));
  }
  if (reduceOpen.length > 0) {
    if (node9Open.length > 0) lines.push('');
    lines.push('  ' + chalk.yellow.bold('🔒 AVAILABLE — turn on to harden (each has a tradeoff)'));
    for (const f of reduceOpen) lines.push(...renderFinding(f, true, openLabel(f)));
  }
  if (osOpen.length > 0) {
    if (node9Open.length > 0 || reduceOpen.length > 0) lines.push('');
    lines.push('  ' + chalk.bold("🧱 YOUR PART — node9 can't fix these (OS-level)"));
    for (const f of osOpen) lines.push(...renderFinding(f, false, openLabel(f)));
  }

  for (const cat of result.passedCategories) {
    lines.push(`  ${chalk.green('✅')} ${label(cat)}${chalk.gray('no issues found')}`);
  }
  for (const cat of result.erroredCategories) {
    lines.push(`  ${chalk.gray('•')}  ${label(cat)}${chalk.gray('could not be checked')}`);
  }

  lines.push('');
  // Footer counts reflect what's still OPEN, not what node9 already covers.
  const crit = open.filter((f) => f.severity === 'critical').length;
  const high = open.filter((f) => f.severity === 'high').length;
  const med = open.filter((f) => f.severity === 'medium').length;
  const adv = open.filter((f) => f.severity === 'advisory').length;
  const parts: string[] = [];
  if (crit) parts.push(chalk.red(`${crit} critical`));
  if (high) parts.push(chalk.red(`${high} high`));
  if (med) parts.push(chalk.yellow(`${med} medium`));
  if (adv) parts.push(chalk.gray(`${adv} advisory`));
  const summary = parts.length ? parts.join(' · ') : chalk.green('no findings');
  lines.push(`  ${summary}`);
  lines.push('');
  lines.push('  ' + chalk.bold('Track this across your fleet & keep it green:'));
  lines.push(
    '  ' + chalk.dim('→ ') + chalk.cyan.underline('https://node9.ai/auth/signup?ref=cli_posture')
  );
  lines.push('');
  return lines.join('\n');
}
