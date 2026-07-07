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
