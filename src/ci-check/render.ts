// src/ci-check/render.ts
// Renderers for a ScanResult — a terminal scorecard (chalk) and a Markdown
// version (for a PR comment later). Attack-story-first, never overclaims: every
// finding shows the signals that fired AND the mitigations seen.

import chalk from 'chalk';
import type { ScanResult, CiFinding, Severity } from './types';

const ICON: Record<Severity, string> = {
  critical: '🔴',
  high: '🔴',
  medium: '🟡',
  advisory: '🟢',
};

const COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  advisory: chalk.gray,
};

// The one continuous-coverage CTA for a repo scan: the GitHub Action runs this
// same check on every PR. node9-proxy (runtime) is intentionally NOT offered
// here — it's a live-agent tool, off-topic for a CI scan, and posture proves a
// single loud CTA converts better than two. ?ref lets us attribute installs.
const ACTION_URL =
  'https://github.com/marketplace/actions/node9-agent-security-check?ref=cli_scan_repo';

/**
 * Closing call-to-action: turn a one-time scan into continuous coverage.
 * Mirrors posture's single-link close, but the verdict line flexes with the
 * result — and an incomplete scan must NOT be dressed up as "clean/green".
 * Presentation only: reads res.worst/res.incomplete, changes no scan logic.
 */
function renderCta(res: ScanResult): string[] {
  const L: string[] = [];
  L.push(chalk.dim('   ' + '─'.repeat(63)));

  // Precedence mirrors the headline ordering above: a real worst-severity wins
  // over `incomplete` (a HIGH we DID read still leads), and only a truly clean,
  // complete scan gets the "green" line.
  if (res.worst === 'critical' || res.worst === 'high') {
    const n = res.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
    L.push(
      '   ' +
        chalk.red.bold(
          `🔴 ${n} ${n === 1 ? 'issue' : 'issues'} to fix — then stop the next at the PR.`
        )
    );
    L.push('');
    L.push('   ' + chalk.bold('Catch this class of issue on every PR, automatically:'));
  } else if (res.worst) {
    L.push('   ' + chalk.yellow('🟡 Review the findings above, then keep it covered:'));
    L.push('');
    L.push('   ' + chalk.bold('Check every PR for agent-CI risk:'));
  } else if (res.incomplete) {
    // Couldn't read every file over the API. The Action scans the checked-out
    // tree in CI (no rate limit), so it's the honest fix for an incomplete scan.
    L.push('   ' + chalk.yellow.bold('⚠️  Incomplete — not a clean bill of health.'));
    L.push('');
    L.push('   ' + chalk.bold('Get a complete check on every PR (CI reads the tree directly):'));
  } else {
    L.push('   ' + chalk.green('✅ Agent CI is well-configured — 0 unmitigated issues.'));
    L.push('');
    L.push('   ' + chalk.bold('Keep it green as you add agent workflows — check every PR:'));
  }

  L.push('   ' + chalk.dim('→ ') + chalk.cyan.underline(ACTION_URL));
  L.push('   ' + chalk.gray('  zero setup · no token · runs in your CI'));
  return L;
}

function ownedHint(source: string): boolean {
  // Heuristic: a local path is "yours"; a github owner/repo we can't know — so
  // we always show the disclosure reminder for HIGH+ on a remote scan.
  return source.startsWith('/') || source.startsWith('.') || source.startsWith('~');
}

export function renderScan(res: ScanResult): string {
  const L: string[] = [];
  const n = res.findings.length;
  // An incomplete scan (rate limit / network) can never be "clean" — it didn't
  // read every file. Say so loudly instead of implying a clean bill of health.
  const head =
    res.worst === 'critical' || res.worst === 'high'
      ? chalk.red.bold('⚠️  agent-security risk found')
      : res.worst
        ? chalk.yellow('agent-security notes')
        : res.incomplete
          ? chalk.yellow.bold('⚠️  INCOMPLETE — could not read all files')
          : chalk.green('✅ agent-security: clean');
  L.push(`🛡️  ${chalk.bold('node9 scan-repo')}  ·  ${res.source}  ·  ${head}`);
  L.push(chalk.gray(`   inspected ${res.inspected.length} config file(s), ${n} finding(s)`));
  if (res.incomplete) {
    // State the ACTUAL cause — a rate limit and a network timeout need different
    // advice (a token fixes the former, not the latter).
    const rateLimited = res.notes.some((nt) => /rate limit/i.test(nt));
    L.push(
      chalk.yellow.bold(
        rateLimited
          ? '   ⚠️  Rate-limited — some files were unread. NOT a clean bill of health; set GITHUB_TOKEN (or run `gh auth login`) and re-run.'
          : '   ⚠️  A network error left some files unread. NOT a clean bill of health; re-run.'
      )
    );
  }
  L.push('');

  for (const f of res.findings) {
    L.push(
      `${ICON[f.severity]} ${COLOR[f.severity](f.severity.toUpperCase())}  ${chalk.bold(f.title)}`
    );
    L.push(chalk.gray(`   ${f.file}${f.line ? ':' + f.line : ''}  ·  ${f.check}`));
    for (const s of f.signals) L.push(`     • ${s}`);
    if (f.mitigations?.length) L.push(chalk.gray(`     ✓ mitigated: ${f.mitigations.join('; ')}`));
    L.push(chalk.cyan(`     → ${f.fix}`));
    L.push('');
  }

  if (n === 0 && !res.incomplete) {
    L.push(
      chalk.gray('   No committed agent hooks, injectable workflows, or unpinned MCP servers.')
    );
    L.push('');
  }

  for (const note of res.notes) L.push(chalk.gray(`   note: ${note}`));

  // Responsible-use reminder on a remote HIGH+ finding.
  const hasHigh = res.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
  if (hasHigh && !ownedHint(res.source)) {
    L.push('');
    L.push(
      chalk.yellow(
        '   ⚠️  This looks like a live issue on a repo you may not own. Disclose it privately\n' +
          '       to the maintainers — do not publish it. (node9 never weaponizes findings.)'
      )
    );
  }

  // Closing CTA — a one-time scan → continuous coverage on every PR.
  L.push('');
  L.push(...renderCta(res));
  return L.join('\n');
}

export function renderScanMarkdown(res: ScanResult): string {
  const L: string[] = [];
  const status =
    res.worst === 'critical' || res.worst === 'high'
      ? '⚠️'
      : res.worst
        ? '🟡'
        : res.incomplete
          ? '⚠️'
          : '✅';
  L.push(`### 🛡️ node9 agent-security · \`${res.source}\` · ${status}`);
  L.push('');
  L.push(
    `Inspected ${res.inspected.length} config file(s) · **${res.findings.length} finding(s)**`
  );
  L.push('');
  for (const f of res.findings) {
    L.push(`**${ICON[f.severity]} ${f.severity.toUpperCase()} — ${f.title}**`);
    L.push(`\`${f.file}${f.line ? ':' + f.line : ''}\` · ${f.check}`);
    L.push('');
    for (const s of f.signals) L.push(`- ${s}`);
    if (f.mitigations?.length) L.push(`- _mitigated:_ ${f.mitigations.join('; ')}`);
    L.push('');
    L.push(`→ **Fix:** ${f.fix}`);
    L.push('');
  }
  if (res.findings.length === 0) L.push('No committed agent-security issues found.');
  // NOTE: intentionally NO Action CTA here. This renders the PR comment posted
  // BY the Action itself — if it's commenting, the Action is already installed,
  // so a "go install the Action" CTA would be redundant and spammy in-PR.
  return L.join('\n');
}

/** Shared by the CLI: pick a picked finding's exit code weight. */
export function exitCodeFor(res: ScanResult): number {
  if (res.worst === 'critical' || res.worst === 'high') return 2;
  if (res.worst === 'medium') return 1;
  if (res.incomplete) return 3; // couldn't read every file — not a clean pass
  return 0;
}

export function pickFinding(findings: CiFinding[]): CiFinding | undefined {
  return findings[0];
}
