// src/ci-check/render.ts
// Renderers for a ScanResult — a terminal scorecard (chalk) and a Markdown
// version (for a PR comment later). Attack-story-first, never overclaims: every
// finding shows the signals that fired AND the mitigations seen.

import chalk from 'chalk';
import { safeText } from './suppress';
import { groupReview, isAlert, reviewQuestion, REVIEW_FILES, REVIEW_LINES_PER_FILE } from './tier';
import type { ScanResult, CiFinding, ScanDiff, Severity } from './types';

/** What the report lists as findings: alerts and notes. Review items go to "Worth a look" (§Q). */
const listed = (fs: CiFinding[]): CiFinding[] => fs.filter((f) => f.tier !== 'review');

/** The quoted text of a finding: its first code span, else its title. */
function excerpt(f: CiFinding): string {
  const m = /`([^`]+)`/.exec(f.signals[0] ?? '');
  return safeText(m ? m[1] : f.title, 120).replace(/`/g, "'");
}

/** The "Worth a look" block, as Markdown. Empty when there is nothing to review. */
function reviewMd(findings: CiFinding[]): string[] {
  const { byFile, grants } = groupReview(findings);
  if (!byFile.size && !grants) return [];
  const L = ['<details><summary><b>🔍 Worth a look (not counted in the result)</b></summary>', ''];
  if (byFile.size) {
    L.push(
      "node9 found text that matches a risky pattern, but in its context it is usually harmless: an install note, a quoted example, documentation. We can't be sure, so we are pointing you at it rather than raising an alert. Please open each place and confirm it is not an instruction to the agent. Where node9 could not read a script, it says so. These items do not change the result."
    );
    L.push('');
    const files = [...byFile.keys()];
    for (const file of files.slice(0, REVIEW_FILES)) {
      const fs = byFile.get(file)!;
      L.push(`- \`${safeText(file, 300)}\``);
      for (const f of fs.slice(0, REVIEW_LINES_PER_FILE))
        L.push(
          `  - ${f.line ? `line ${Number(f.line)}: ` : ''}\`${excerpt(f)}\`. Check: ${reviewQuestion(f.rule)}`
        );
      if (fs.length > REVIEW_LINES_PER_FILE)
        L.push(`  - and ${fs.length - REVIEW_LINES_PER_FILE} similar lines in this file`);
    }
    const more = files.length - REVIEW_FILES;
    if (more > 0) L.push(`- and ${more} more file${more === 1 ? '' : 's'}`);
  }
  if (grants) {
    L.push('');
    L.push(
      `${grants} skill${grants === 1 ? ' is' : 's are'} granted broad tools (Bash, Write or Edit). For most skills that matches what the skill does; check the ones that should only read.`
    );
  }
  L.push('', '</details>', '');
  return L;
}

/** The "Worth a look" block for the terminal: one counted line, then the places. */
function reviewTerminal(findings: CiFinding[]): string[] {
  const { byFile, grants } = groupReview(findings);
  const items = [...byFile.values()].reduce((a, fs) => a + fs.length, 0);
  if (!items && !grants) return [];
  const L: string[] = [];
  if (items) {
    L.push(
      chalk.bold(`🔍 ${items} ${items === 1 ? 'item' : 'items'} worth a look (not counted)`) +
        chalk.gray(': risky-looking text in a context that is usually harmless. Please confirm.')
    );
    const files = [...byFile.keys()];
    for (const file of files.slice(0, REVIEW_FILES)) {
      const fs = byFile.get(file)!;
      L.push(chalk.gray(`   ${file}`));
      for (const f of fs.slice(0, REVIEW_LINES_PER_FILE))
        L.push(`     • ${f.line ? `line ${f.line}: ` : ''}${excerpt(f)}`);
      if (fs.length > REVIEW_LINES_PER_FILE)
        L.push(chalk.gray(`     and ${fs.length - REVIEW_LINES_PER_FILE} similar lines`));
    }
    const more = files.length - REVIEW_FILES;
    if (more > 0) L.push(chalk.gray(`   and ${more} more file${more === 1 ? '' : 's'}`));
  }
  if (grants)
    L.push(
      chalk.gray(
        `   ${grants} skill${grants === 1 ? ' is' : 's are'} granted broad tools (Bash, Write or Edit); usually what the skill needs.`
      )
    );
  L.push('');
  return L;
}

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
// The listing is node9-agent-security, which installs node9-ai/node9-proxy@v2. It
// used to be node9-agent-security-check, which went dead with the archived
// agent-security-action repo; README.md states the same address, and a test
// keeps the two from drifting apart again.
export const ACTION_URL =
  'https://github.com/marketplace/actions/node9-agent-security?ref=cli_scan_repo';

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
    const n = res.findings.filter(
      (f) => isAlert(f) && !f.suppressed && (f.severity === 'critical' || f.severity === 'high')
    ).length;
    L.push(
      '   ' +
        chalk.red.bold(
          `🔴 ${n} ${n === 1 ? 'issue' : 'issues'} to fix, then stop the next at the PR.`
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
    L.push('   ' + chalk.yellow.bold('⚠️  Incomplete: not a clean bill of health.'));
    L.push('');
    L.push('   ' + chalk.bold('Get a complete check on every PR (CI reads the tree directly):'));
  } else {
    L.push(
      '   ' +
        chalk.green(
          groupReview(res.findings).byFile.size
            ? '✅ No alerts. Check the items worth a look above.'
            : '✅ Agent CI is well-configured: 0 unmitigated issues.'
        )
    );
    L.push('');
    L.push('   ' + chalk.bold('Keep it green as you add agent workflows. Check every PR:'));
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

/** One finding, as Markdown. Shared by the absolute and the diff renderers so the two can
 *  never drift in how a finding reads. */
/** One line of markdown built partly from repo text (§P3; the same rule as comment.js): no
 *  line breaks; outside code spans, no HTML start and no @-mention. Code spans are left as they
 *  are, so a command in one copies exactly. */
export function mdLine(v: unknown): string {
  return String(v)
    .replace(/[\r\n\u2028\u2029]+/g, ' ')
    .replace(/(`[^`]*`)|([^`]+)/g, (_m, code: string | undefined, text: string | undefined) =>
      code
        ? code
        : (text ?? '')
            .replace(/<(?=[!/?A-Za-z])/g, '<\u200b')
            .replace(/(^|[^A-Za-z0-9_])@(?=[A-Za-z0-9])/g, '$1@\u200b')
    );
}

function findingMd(f: CiFinding, L: string[]): void {
  const ex = f.explain;
  L.push(
    `**${ICON[f.severity]} ${f.severity.toUpperCase()}: ${mdLine(ex ? ex.headline : f.title)}**` +
      (f.suppressed ? ` _(suppressed: \`${safeText(f.suppressed.reason, 200)}\`)_` : '')
  );
  L.push(`\`${safeText(f.file, 300)}${f.line ? ':' + Number(f.line) : ''}\`  ·  ${f.rule}`);
  L.push('');
  if (ex) {
    // Plain words first (design R); the check's own record follows, collapsed.
    L.push(mdLine(ex.happens), '', '**What we saw:**');
    for (const s of ex.saw) L.push(`- ${mdLine(s)}`);
    L.push('', '**✅ How to fix:**');
    ex.fix.forEach((x, i) => L.push(`${i + 1}. ${mdLine(x)}`));
    L.push('', '<details><summary>Technical details</summary>', '');
  }
  for (const s of f.signals) L.push(`- ${mdLine(s)}`);
  if (f.mitigations?.length) L.push(`- _mitigated:_ ${mdLine(f.mitigations.join('; '))}`);
  L.push('');
  L.push(`→ **Fix:** ${f.fix}`);
  L.push('');
  if (ex) L.push('</details>', '');
}

/** Why a diff could not be trusted, in the reviewer's words. Never rendered as "clean". */
function baseWarning(base: ScanDiff['base']): string {
  return base === 'did-not-run'
    ? '⚠️ **Could not read the base commit**, so nothing below can be called "new". Every finding in this repo is listed. (A shallow clone is the usual cause: fetch the base ref.)'
    : '⚠️ **The base scan could not read every file**, so a finding missing from it would look new. Every finding in this repo is listed instead.';
}

export function renderScan(res: ScanResult, diff?: ScanDiff): string {
  const L: string[] = [];
  const shown = listed(res.findings);
  const n = shown.length;
  // An incomplete scan (rate limit / network) can never be "clean" — it didn't
  // read every file. Say so loudly instead of implying a clean bill of health.
  const head =
    res.worst === 'critical' || res.worst === 'high'
      ? chalk.red.bold('⚠️  agent-security risk found')
      : res.worst
        ? chalk.yellow('agent-security notes')
        : res.incomplete
          ? chalk.yellow.bold('⚠️  INCOMPLETE: could not read all files')
          : groupReview(res.findings).byFile.size
            ? chalk.green('✅ agent-security: no alerts (items worth a look below)')
            : chalk.green('✅ agent-security: clean');
  L.push(`🛡️  ${chalk.bold('node9 scan-repo')}  ·  ${res.source}  ·  ${head}`);
  L.push(
    chalk.gray(
      `   inspected ${res.inspected.length} config file(s), ${n} finding(s)` +
        (res.suppressedCount ? ` · ${res.suppressedCount} suppressed by .node9-ignore.json` : '')
    )
  );
  if (diff) {
    const introduced = listed(diff.added).length + diff.escalated.length;
    L.push(
      diff.base !== 'ok'
        ? chalk.yellow.bold(
            `   ⚠️  base ${diff.base === 'did-not-run' ? 'could not be read' : 'scan was incomplete'}, so it cannot say what is new; showing everything`
          )
        : introduced > 0
          ? chalk.red.bold(
              `   ⚠️  this change introduced ${introduced} finding(s)` +
                (diff.escalated.length
                  ? ` (${diff.escalated.length} by widening an existing one)`
                  : '')
            )
          : chalk.green(
              `   ✅ this change introduced nothing` +
                (diff.unchanged.length ? ` (${diff.unchanged.length} pre-existing)` : '') +
                (diff.removed.length ? `, and fixed ${diff.removed.length}` : '')
            )
    );
  }
  if (res.incomplete) {
    // State the ACTUAL cause — a rate limit and a network timeout need different
    // advice (a token fixes the former, not the latter).
    const rateLimited = res.notes.some((nt) => /rate limit/i.test(nt));
    L.push(
      chalk.yellow.bold(
        rateLimited
          ? '   ⚠️  Rate-limited: some files were unread. NOT a clean bill of health; set GITHUB_TOKEN (or run `gh auth login`) and re-run.'
          : '   ⚠️  A network error left some files unread. NOT a clean bill of health; re-run.'
      )
    );
  }
  L.push('');

  for (const f of shown) {
    const ex = f.explain;
    L.push(
      `${ICON[f.severity]} ${COLOR[f.severity](f.severity.toUpperCase())}  ${chalk.bold(ex ? ex.headline : f.title)}`
    );
    L.push(chalk.gray(`   ${f.file}${f.line ? ':' + f.line : ''}  ·  ${f.check}`));
    if (ex) {
      // Plain words (design R): what can happen, what was seen, how to fix.
      L.push(`     ${ex.happens}`);
      for (const s of ex.saw) L.push(`     • ${s}`);
      ex.fix.forEach((x, i) => L.push(chalk.cyan(`     ${i + 1}. ${x}`)));
    } else {
      for (const s of f.signals) L.push(`     • ${s}`);
      if (f.mitigations?.length)
        L.push(chalk.gray(`     ✓ mitigated: ${f.mitigations.join('; ')}`));
      L.push(chalk.cyan(`     → ${f.fix}`));
    }
    L.push('');
  }

  if (n === 0 && !res.incomplete) {
    L.push(
      chalk.gray('   No committed agent hooks, injectable workflows, or unpinned MCP servers.')
    );
    L.push('');
  }

  L.push(...reviewTerminal(res.findings));

  for (const note of res.notes) L.push(chalk.gray(`   note: ${note}`));

  // Responsible-use reminder on a remote HIGH+ finding.
  const hasHigh = shown.some(
    (f) => isAlert(f) && !f.suppressed && (f.severity === 'critical' || f.severity === 'high')
  );
  if (hasHigh && !ownedHint(res.source)) {
    L.push('');
    L.push(
      chalk.yellow(
        '   ⚠️  This looks like a live issue on a repo you may not own. Disclose it privately\n' +
          '       to the maintainers; do not publish it. (node9 never weaponizes findings.)'
      )
    );
  }

  // Closing CTA — a one-time scan → continuous coverage on every PR.
  L.push('');
  L.push(...renderCta(res));
  return L.join('\n');
}

export function renderScanMarkdown(res: ScanResult, diff?: ScanDiff): string {
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
  const shown = listed(res.findings);
  L.push(
    `Inspected ${res.inspected.length} config file(s) · **${shown.length} finding(s)**` +
      (res.suppressedCount ? ` · ${res.suppressedCount} suppressed by \`.node9-ignore.json\`` : '')
  );
  L.push('');
  // CI-5: lead with what THIS change is answerable for. A reviewer cannot act on a repo's
  // accumulated history, and burying the one new finding under twelve old ones is how a
  // gate gets muted. Pre-existing findings stay in the comment — collapsed, not deleted.
  if (diff && diff.base === 'ok') {
    const introduced = [...listed(diff.added), ...diff.escalated.map((e) => e.finding)];
    if (introduced.length === 0) {
      L.push(
        `✅ **This change introduces no agent-security findings.**` +
          (diff.removed.length ? ` It also fixes ${diff.removed.length}.` : '')
      );
      L.push('');
    } else {
      L.push(`#### ⚠️ Introduced by this change: ${introduced.length} finding(s)`);
      L.push('');
      for (const f of listed(diff.added)) findingMd(f, L);
      for (const e of diff.escalated) {
        L.push(
          `> _Guardrail erosion: this finding already existed at **${e.from}** and this change widens it to **${e.to}**._`
        );
        L.push('');
        findingMd(e.finding, L);
      }
    }
    if (diff.removed.length) {
      L.push(`✅ Fixed by this change: ${diff.removed.length} finding(s).`);
      L.push('');
    }
    if (listed(diff.unchanged).length) {
      L.push(
        `<details><summary>${listed(diff.unchanged).length} pre-existing finding(s), not introduced by this change</summary>`
      );
      L.push('');
      for (const f of listed(diff.unchanged)) findingMd(f, L);
      L.push('</details>');
      L.push('');
    }
    // What this change adds; old review items are not news.
    L.push(...reviewMd(diff.added));
    return L.join('\n');
  }

  if (diff) {
    L.push(baseWarning(diff.base));
    L.push('');
  }
  for (const f of shown) findingMd(f, L);
  if (shown.length === 0) L.push('No committed agent-security issues found.');
  L.push(...reviewMd(res.findings));
  // NOTE: intentionally NO Action CTA here. This renders the PR comment posted
  // BY the Action itself — if it's commenting, the Action is already installed,
  // so a "go install the Action" CTA would be redundant and spammy in-PR.
  return L.join('\n');
}

/** The CLI's one exit-code law, in terms of a severity + whether the scan finished.
 *  Shared by the absolute gate and the `--fail-on-introduced` gate so the same severity
 *  can never block on one and pass on the other. */
export function exitCodeForSeverity(worst: Severity | null, incomplete: boolean): number {
  if (worst === 'critical' || worst === 'high') return 2;
  if (worst === 'medium') return 1;
  if (incomplete) return 3; // couldn't read every file — not a clean pass
  return 0;
}

/** Shared by the CLI: pick a picked finding's exit code weight. */
export function exitCodeFor(res: ScanResult): number {
  return exitCodeForSeverity(res.worst, res.incomplete);
}

export function pickFinding(findings: CiFinding[]): CiFinding | undefined {
  return findings[0];
}
