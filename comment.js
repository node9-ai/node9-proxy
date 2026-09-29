// comment.js — posts a sticky PR comment + a Checks-API check-run from a
// `node9 scan-repo --json` result, and applies the `fail-on` gate.
//
// Dependency-free (Node 20 global fetch). Pure logic (render/decide) is split
// from I/O so it can be self-tested: `node comment.js --selftest`.
//
// Design note: this runs in the PRIVILEGED comment step but only ever handles
// the RESULT JSON (data) — never the repo's code — so it's safe by construction.

'use strict';
const fs = require('fs');

const MARKER = '<!-- node9-agent-security -->';
const CHECK_NAME = 'node9 agent-security';
const RANK = { critical: 4, high: 3, medium: 2, advisory: 1 };
const ICON = { critical: '🔴', high: '🔴', medium: '🟡', advisory: '🟢' };

// ── Pure logic ──────────────────────────────────────────────────────────────

/** Decide the check-run conclusion + process exit from the worst severity and
 *  the fail-on threshold. `never` = report-only (never fails). */
function decide(worst, failOn, incomplete = false) {
  const threshold = RANK[failOn]; // undefined for 'never'/unknown → never fail
  const fail = !!(threshold && worst && RANK[worst] >= threshold);
  // A scan that could not read every file has not earned a green check. It does not FAIL
  // the gate (we have no evidence of a problem), but it must not report success either —
  // "nothing found" is a statement about what we read, not about the change.
  const conclusion = fail ? 'failure' : worst || incomplete ? 'neutral' : 'success';
  return { fail, conclusion, exitCode: fail ? 1 : 0 };
}

/** Which severity the gate judges. `all` (the default) keeps the pre-CI-5 behaviour
 *  exactly: the repo's worst finding. `introduced` narrows it to what THIS change is
 *  answerable for, which is what lets a repo that is already dirty turn the gate on today.
 *
 *  The scan already degrades `worstIntroduced` to the head's absolute worst when the base
 *  could not be read, so an unreadable base falls back to the strict answer here rather
 *  than passing as "nothing new". Missing diff (an older CLI than this action) → `all`. */
/** A value from the scanned repo (a suppression reason) made safe inside a backtick span:
 *  one line, no backtick, bounded. Inside a code span GitHub renders `<!--`, `###` and
 *  `@team` literally, so the reason cannot forge a header, hide findings or ping anyone. */
function safeInline(v) {
  return String(v)
    .replace(/[\r\n\u2028\u2029]+/g, ' ')
    .replace(/`/g, "'")
    .slice(0, 200);
}

// ── Tiers (§Q) ──────────────────────────────────────────────────────────────
// Only alerts decide the result. Review items are patterns found in context that is usually
// harmless (an install note, a quoted example, docs): listed plainly under "Worth a look", never
// counted. A finding without a tier (an older CLI) counts as an alert.
const isAlert = (f) => !f.tier || f.tier === 'alert';
const isReview = (f) => f.tier === 'review';
const GRANT_RULE = 'CI-1.skill-allowed-tools';
const REVIEW_FILES = 10;
const REVIEW_LINES_PER_FILE = 3;
/** One check question per kind, so a reviewer knows what to look for. */
function reviewQuestion(rule) {
  if (/fetch-and-obey|remote-exec/.test(rule))
    return "Is the agent told to run this, or is it a note for a person? Is the source the vendor's own?";
  if (/prompt-override/.test(rule)) return 'Is this aimed at the model, or quoted as an example?';
  if (/exfil/.test(rule)) return "Where does the data go: your own service, or someone else's?";
  if (/secret/.test(rule))
    return 'Is the agent asked to read or send the file, or is it only named?';
  if (/hook-script-missing/.test(rule))
    return 'Does this hook exist on every machine that runs it?';
  if (/hidden-chars/.test(rule))
    return 'Why does this script hold invisible characters? A list of them to detect is fine.';
  if (/unscanned/.test(rule))
    return 'node9 did not read this script (too large, or outside the folders it reads). What does it run?';
  return 'Is this an instruction the agent follows, or text for a person?';
}
/** The quoted text of a finding: its first code span, else its title. */
function excerpt(f) {
  const m = /`([^`]+)`/.exec((f.signals || [])[0] || '');
  return safeInline(m ? m[1] : f.title).slice(0, 120);
}
/** The "Worth a look" section: grouped per file, at most REVIEW_FILES files, a skill-grant line. */
/** The review items this comment lists. On a PR with a readable base, only what the PR adds: old
 *  review items are not news. */
function reviewItems(result) {
  const d = result.diff;
  const source =
    d && d.base === 'ok' ? d.added || [] : Array.isArray(result.findings) ? result.findings : [];
  return source.filter((f) => !f.suppressed && isReview(f));
}
/** "and N items worth a look below", for a headline that has no alert to lead with. */
function reviewTail(result) {
  const n = reviewItems(result).length;
  return n ? ` ${n} item${n === 1 ? '' : 's'} worth a look below.` : '';
}
function renderReview(result) {
  const items = reviewItems(result);
  const grants = items.filter((f) => f.rule === GRANT_RULE);
  const rest = items.filter((f) => f.rule !== GRANT_RULE);
  if (!rest.length && !grants.length) return '';
  const L = ['<details><summary><b>🔍 Worth a look (not counted in the result)</b></summary>', ''];
  if (rest.length) {
    L.push(
      "node9 found text that matches a risky pattern, but in its context it is usually harmless: an install note, a quoted example, documentation. We can't be sure, so we are pointing you at it rather than raising an alert. Please open each place and confirm it is not an instruction to the agent. Where node9 could not read a script, it says so. These items do not change the result."
    );
    L.push('');
    const byFile = new Map();
    for (const f of rest) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      byFile.get(f.file).push(f);
    }
    // The files most worth opening first: the worst item, then the most items.
    const worstRank = (fs) => Math.max(...fs.map((f) => RANK[f.severity] || 0));
    const files = [...byFile.keys()].sort(
      (x, y) =>
        worstRank(byFile.get(y)) - worstRank(byFile.get(x)) ||
        byFile.get(y).length - byFile.get(x).length
    );
    for (const file of files.slice(0, REVIEW_FILES)) {
      const fs = byFile.get(file);
      L.push(`- \`${safeInline(file)}\``);
      for (const f of fs.slice(0, REVIEW_LINES_PER_FILE))
        L.push(
          `  - ${f.line ? `line ${Number(f.line)}: ` : ''}\`${excerpt(f)}\`. Check: ${reviewQuestion(f.rule)}`
        );
      if (fs.length > REVIEW_LINES_PER_FILE)
        L.push(`  - and ${fs.length - REVIEW_LINES_PER_FILE} similar lines in this file`);
    }
    if (files.length > REVIEW_FILES)
      L.push(
        `- and ${files.length - REVIEW_FILES} more file${files.length - REVIEW_FILES === 1 ? '' : 's'}`
      );
  }
  if (grants.length) {
    L.push('');
    L.push(
      `${grants.length} skill${grants.length === 1 ? ' is' : 's are'} granted broad tools (Bash, Write or Edit). For most skills that matches what the skill does; check the ones that should only read.`
    );
  }
  L.push('');
  L.push('</details>');
  return L.join('\n');
}

// ── An incomplete scan (§O, founder decision 2026-09-27) ────────────────────────
// A PR author can make a scan incomplete (padding, caps, budgets). The conclusion is neutral,
// never success; everything the reviewer reads must say the same, and say WHAT was not read.
const INCOMPLETE_NOTE_RE = /may be INCOMPLETE/i;
function isIncomplete(result) {
  return !!(result.incomplete || (result.diff && result.diff.incomplete));
}
/** The scan's own reasons for being partial: the notes that carry "may be INCOMPLETE". */
function unreadNotes(result) {
  const notes = Array.isArray(result.notes) ? result.notes : [];
  return [...new Set(notes.map(String).filter((n) => INCOMPLETE_NOTE_RE.test(n)))];
}
/** The reasons as a markdown list: at most 5, each an inert code span (file names are the PR
 *  author's), then how many more. */
function unreadList(result) {
  const notes = unreadNotes(result);
  const L = notes.slice(0, 5).map((n) => `- \`${safeInline(n)}\``);
  if (notes.length > 5) L.push(`- and ${notes.length - 5} more`);
  if (!notes.length) L.push('- (the scan did not say which files)');
  return L.join('\n');
}
function unreadBlock(result) {
  return [
    "**⚠️ node9 could not read everything.** It did not finish reading this repository's agent configuration, so it cannot say this PR is clean. Not read:",
    unreadList(result),
  ].join('\n');
}
/** GitHub workflow-command data: `%`, CR and LF must be escaped, or a note could end the
 *  command and start another. */
function escapeCommandData(v) {
  return String(v).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}
/** One Actions-log warning for an incomplete scan; null for a complete one. */
function incompleteWarning(result) {
  if (!isIncomplete(result)) return null;
  const first = unreadNotes(result)[0] || 'the scan did not finish reading every file';
  return `::warning title=node9 could not read everything::${escapeCommandData(first.slice(0, 300))}`;
}

// ── Repo text in the comment (§P3) ────────────────────────────────────────────
// A finding's file path, title and signals carry text from the scanned repository (an MCP
// server name, a permission entry, a workflow trigger, a command). Rendered as-is it could forge
// a header, hide the rest of the comment with `<!--`, ping a team, or break out of a code span.
// Made inert HERE, where it is rendered, so no analyzer has to get it right on its own.

/** One line of markdown built partly from repo text: no line breaks; outside code spans, no
 *  HTML start (`<!--`, `<tag`) and no @-mention. Code spans are left as they are — their text
 *  is literal, and a command in one must copy exactly. */
function mdLine(v) {
  return String(v)
    .replace(/[\r\n\u2028\u2029]+/g, ' ')
    .replace(/(`[^`]*`)|([^`]+)/g, (m, code, text) =>
      code
        ? code
        : text
            .replace(/<(?=[!/?A-Za-z])/g, '<\u200b')
            .replace(/(^|[^A-Za-z0-9_])@(?=[A-Za-z0-9])/g, '$1@\u200b')
    );
}
/** A workflow-command property value (`file=`, `title=`): `%`, CR, LF, `:` and `,` escaped. */
function escapeCommandProperty(v) {
  return escapeCommandData(v).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

/** Why the Action did not scan, in the reviewer's words, with the one-line fix. */
const SKIP_REASONS = {
  pull_request_target:
    'this workflow runs on `pull_request_target`, which checks out the base branch, so the changes in this PR are not visible to the scan. Run this Action on `pull_request` instead.',
};

/** The sticky comment when the Action deliberately did not scan. Never reads as clean. */
function renderSkipped(reason) {
  const why = SKIP_REASONS[reason] || `the scan was skipped (${safeInline(reason)}).`;
  return [
    MARKER,
    '### 🛡️ node9 agent-security · ⚪ node9 did not scan this PR',
    '',
    `node9 did not scan this PR: ${why}`,
  ].join('\n');
}

/** A skipped scan neither passes nor blocks: neutral, exit 0 (founder decision 2026-09-27). */
function decideSkipped() {
  return { fail: false, conclusion: 'neutral', exitCode: 0 };
}

function gateWorst(result, scope) {
  if (scope !== 'introduced' || !result.diff) return result.worst;
  return result.diff.worstIntroduced ?? null;
}

/** The findings a reviewer should be annotated about: what this change introduced, or
 *  everything when there is no trustworthy diff. */
function annotatable(result) {
  const d = result.diff;
  const all =
    !d || d.base !== 'ok'
      ? Array.isArray(result.findings)
        ? result.findings
        : []
      : [...(d.added || []), ...(d.escalated || []).map((e) => e.finding)];
  // A suppressed finding is a reviewed decision: it stays in the collapsed list, not on the diff.
  // Only alerts are annotated (§Q): a review item is listed in the comment, not on the diff.
  return all.filter((f) => !f.suppressed && isAlert(f));
}

/** GitHub workflow commands: one annotation per finding, on the file in the PR diff.
 *  No API call and no `checks: write` permission needed — the runner parses stdout.
 *  Findings carry no line number today, so these anchor at the file (line 1); adding
 *  real line numbers to the checks upgrades these in place. */
function annotationLines(result) {
  const level = { critical: 'error', high: 'error', medium: 'warning', advisory: 'notice' };
  return annotatable(result).map(
    (f) =>
      `::${level[f.severity] || 'notice'} file=${escapeCommandProperty(f.file)},line=${Number(f.line) || 1},title=${escapeCommandProperty(`node9 ${f.rule || f.check}`)}::${escapeCommandData(f.title)}`
  );
}

/** Derive a one-line, severity-TIERED threat sentence from the anchor finding (+ its
 *  same-file companions, so a CI-2 injection + a CI-4 secret on one file tell ONE story).
 *  Derived from severity + check + signals — NEVER a fixed scary template — so it cannot
 *  overclaim: only a critical/high says "a stranger can…"; a medium is calm; an advisory is
 *  neutral. This honesty is the whole risk of the feature. */
function threatLine(anchor, companions) {
  const sev = anchor.severity;
  const sig = companions
    .flatMap((c) => c.signals || [])
    .join(' | ')
    .toLowerCase();
  const rce = /arbitrary shell|bare bash|broad\/write-capable tools \(bash/.test(sig);
  const exfil = companions.some((c) => c.check === 'CI-4') || /exfiltrat|read env/.test(sig);
  const codeWrite = /checks out the untrusted pr head into the workspace root|contents.*write/.test(
    sig
  );
  const prWrite = /pull-requests|approve or merge|merge a/.test(sig);

  switch (anchor.check) {
    case 'CI-2':
    case 'CI-4':
      if (sev === 'critical')
        return rce && exfil
          ? 'A stranger can run code on this repo and steal your secrets.'
          : rce
            ? 'A stranger can run arbitrary code on this repo through your agent.'
            : codeWrite
              ? 'A stranger can get your agent to push code to this repo.'
              : "A stranger can make your agent take privileged actions with your repo's secrets.";
      if (sev === 'high')
        return prWrite
          ? 'A stranger can make your agent approve or merge pull requests.'
          : "A stranger can make your agent act with your repo's write permissions.";
      if (sev === 'medium')
        return 'Hardening: this agent workflow would become exploitable if an untrusted trigger or broader tools were added.';
      return 'A minor hardening note on an agent workflow.';
    case 'CI-1':
      return sev === 'high'
        ? "This repo pre-authorizes every contributor's agent to run broad tools (Bash/Write) with no deny backstop."
        : 'A committed agent config grants broad tools. It is worth scoping down.';
    case 'CI-3':
      return "An MCP server runs an unpinned package: a compromised release would run in every contributor's agent.";
    case 'CI-6':
      if (sev === 'critical')
        return 'An agent instruction file hides characters that conceal instructions from human review.';
      if (sev === 'high')
        return 'An agent instruction file tells the agent to ignore its own rules.';
      if (sev === 'medium')
        return 'An agent instruction file points the agent at a risky action. Review it.';
      return 'A minor note on an agent instruction file.';
    default:
      return RANK[sev] >= RANK.high
        ? 'An agent-security risk needs your attention.'
        : 'A minor agent-security hardening note.';
  }
}

/** One derived, plain-English sentence on the MECHANISM (why it's reachable) — a general,
 *  faithful restatement, not an invented exploit script. Tiered: crit/high explain the
 *  exposure; medium/advisory stay calm. */
function mechanism(anchor, companions) {
  const sev = anchor.severity;
  const calm = RANK[sev] <= RANK.medium;
  switch (anchor.check) {
    case 'CI-2':
    case 'CI-4':
      return calm
        ? "It's gated or scoped today, but a small change (an untrusted trigger, or broader tools) would open it."
        : "Anyone who can trigger this workflow reaches the agent, and it runs with your repo's permissions. No human approves first.";
    case 'CI-1':
      return 'It ships in the repo, so it applies to every contributor who runs the agent here.';
    case 'CI-3':
      return "It's fetched fresh on every run, so whoever controls that package controls the agent.";
    case 'CI-6':
      return "It's loaded into the agent's instructions automatically, on every run.";
    default:
      return '';
  }
}

/** A finding in plain words, as the CLI's explain.ts wrote it: what is wrong, what can happen,
 *  what was seen, how to fix it. Repository text in it sits in code spans; mdLine keeps them
 *  as they are and neutralizes HTML and @-mentions outside them. */
function hasExplain(f) {
  const ex = f && f.explain;
  return (
    !!ex &&
    typeof ex.headline === 'string' &&
    typeof ex.happens === 'string' &&
    Array.isArray(ex.saw) &&
    Array.isArray(ex.fix)
  );
}
function renderExplain(f, L) {
  const ex = f.explain;
  L.push(`**${mdLine(ex.headline)}**`, '', mdLine(ex.happens), '');
  L.push(`**What we saw** in \`${safeInline(f.file)}${f.line ? ':' + Number(f.line) : ''}\`:`);
  for (const s of ex.saw) L.push(`- ${mdLine(s)}`);
  L.push('', '**✅ How to fix:**');
  ex.fix.forEach((x, i) => L.push(`${i + 1}. ${mdLine(x)}`));
}

/** The collapsed fact-list — the previous renderComment body, kept verbatim for power users. */
function renderDetail(result) {
  const findings = (Array.isArray(result.findings) ? result.findings : []).filter(
    (f) => !isReview(f)
  );
  const L = [];
  L.push(
    `<details><summary>${findings.length} finding(s) · ${[...new Set(findings.map((f) => f.check))].join(', ')} · technical details</summary>`
  );
  L.push('');
  for (const f of findings) {
    L.push(
      `**${ICON[f.severity] ?? '•'} ${String(f.severity).toUpperCase()}: ${mdLine(f.title)}**` +
        (f.suppressed ? ` _(suppressed: \`${safeInline(f.suppressed.reason)}\`)_` : '')
    );
    L.push(`\`${safeInline(f.file)}${f.line ? ':' + Number(f.line) : ''}\` · ${f.check}`);
    for (const s of f.signals ?? []) L.push(`- ${mdLine(s)}`);
    if (f.mitigations?.length) L.push(`- _mitigated:_ ${mdLine(f.mitigations.join('; '))}`);
    if (f.fix) L.push(`- → **Fix:** ${f.fix}`);
    L.push('');
  }
  L.push('</details>');
  return L.join('\n');
}

/** Render the sticky comment: lead with the ATTACK STORY (threat → mechanism → single fix),
 *  raw findings collapsed into <details>. Same ScanResult data, reframed for impact. */
function renderComment(result) {
  const review = renderReview(result);
  const withReview = (L) => {
    if (review) L.push('', review);
    return L.join('\n');
  };
  const all = (Array.isArray(result.findings) ? result.findings : []).filter(
    (f) => !f.suppressed && isAlert(f)
  );
  const suppressedN = (Array.isArray(result.findings) ? result.findings : []).filter(
    (f) => f.suppressed
  ).length;
  const notesN = (Array.isArray(result.findings) ? result.findings : []).filter(
    (f) => !f.suppressed && f.tier === 'note'
  ).length;
  const d = result.diff;
  const trusted = d && d.base === 'ok';
  // CI-5: when we know what this change introduced, the comment is about THAT. A reviewer
  // cannot act on the repo's accumulated history, and burying the one new finding under
  // twelve old ones is how a gate gets muted. Pre-existing findings stay in the comment —
  // collapsed inside <details>, never deleted.
  const findings = trusted ? annotatable(result) : all;
  const worst = trusted ? d.worstIntroduced : result.worst;
  const L = [MARKER];
  // An incomplete scan can never take the green branch, however little it found.
  if (trusted && findings.length === 0 && !d.incomplete && !result.incomplete) {
    L.push(`### 🛡️ node9 agent-security · ✅${suppressedN ? ` · ${suppressedN} suppressed` : ''}`);
    L.push('');
    L.push(
      `**This PR introduces no agent-security ${reviewItems(result).length ? 'alerts' : 'findings'}.**` +
        ((d.removed || []).length ? ` It also fixes ${d.removed.length}.` : '') +
        reviewTail(result)
    );
    if ((d.unchanged || []).length) {
      L.push('');
      L.push(
        `<sub>${d.unchanged.length} pre-existing finding(s) in this repo were not introduced by this PR.</sub>`
      );
    }
    L.push('');
    L.push(renderDetail(result));
    return withReview(L);
  }
  const partial = isIncomplete(result);
  if (d && !trusted) {
    L.push(
      d.base === 'did-not-run'
        ? '<sub>⚠️ Could not read the base commit, so nothing below can be called new. Every finding in this repo is listed. A shallow clone is the usual cause.</sub>'
        : '<sub>⚠️ The base scan could not read every file, so a finding missing from it would look new. Every finding in this repo is listed.</sub>'
    );
    L.push('');
  }
  if (findings.length === 0 && partial) {
    L.push(
      `### 🛡️ node9 agent-security · ⚠️ could not read everything${suppressedN ? ` · ${suppressedN} suppressed` : ''}`
    );
    L.push('');
    L.push(unreadBlock(result));
    if (suppressedN || notesN) {
      L.push('');
      L.push(renderDetail(result));
    }
    return withReview(L);
  }
  if (findings.length === 0) {
    L.push(`### 🛡️ node9 agent-security · ✅${suppressedN ? ` · ${suppressedN} suppressed` : ''}`);
    L.push('');
    L.push(
      suppressedN
        ? `No unsuppressed agent-security findings. ${suppressedN} finding(s) are suppressed by \`.node9-ignore.json\` and listed below with their reasons.`
        : reviewTail(result)
          ? `No agent-security alerts.${reviewTail(result)}`
          : 'No agent-security findings: no injectable workflows, unsafe agent configs, or unpinned MCP servers.'
    );
    // Notes (a gated workflow) are not counted, but they are shown.
    if (suppressedN || notesN) {
      L.push('');
      L.push(renderDetail(result));
    }
    return withReview(L);
  }
  const anchor = [...findings].sort((a, b) => RANK[b.severity] - RANK[a.severity])[0];
  const companions = findings.filter((f) => f.file === anchor.file); // chain-merge same-file findings
  const tier =
    worst === 'critical'
      ? 'Critical: action needed'
      : worst === 'high'
        ? 'High: action needed'
        : worst === 'medium'
          ? 'Medium: hardening'
          : 'Advisory: note';

  L.push(
    `### 🛡️ node9 agent-security · ${ICON[worst] ?? '🟢'} ${tier}` +
      (trusted ? ` · introduced by this PR` : '') +
      (suppressedN ? ` · ${suppressedN} suppressed` : '')
  );
  if (trusted && (d.escalated || []).length) {
    L.push('');
    L.push(
      `_${d.escalated.length} of these already existed and this PR widens them: a guardrail was removed, not added._`
    );
  }
  if (partial) {
    L.push('');
    L.push(unreadBlock(result));
  }
  L.push('');
  if (hasExplain(anchor)) {
    // Plain words first (design R); the technical record stays in the collapsed detail.
    renderExplain(anchor, L);
    const others = findings.filter((f) => f !== anchor);
    if (others.length) {
      L.push('', '**Also found:**');
      for (const f of others)
        L.push(
          `- ${ICON[f.severity] ?? '•'} ${mdLine(hasExplain(f) ? f.explain.headline : f.title)} (\`${safeInline(f.file)}\`)`
        );
    }
  } else {
    L.push(`**${threatLine(anchor, companions)}**`);
    const mech = mechanism(anchor, companions);
    if (mech) {
      L.push('');
      L.push(mech);
    }
    const fixes = [...new Set(companions.map((f) => f.fix).filter(Boolean))];
    if (fixes.length === 1) {
      L.push('');
      L.push(`**✅ Fix** in \`${safeInline(anchor.file)}\`: ${fixes[0]}`);
    } else if (fixes.length > 1) {
      L.push('');
      L.push(`**✅ Fix** in \`${safeInline(anchor.file)}\`:`);
      for (const fx of fixes) L.push(`- ${fx}`);
    }
  }
  L.push('');
  L.push(renderDetail(result));
  if (review) L.push('', review);
  L.push('');
  L.push(
    "<sub>node9 scans committed agent config statically and never runs your repo's code. · Catch this on every PR → node9.ai</sub>"
  );
  return L.join('\n');
}

/** A check-run output summary (title + short body). */
function checkSummary(result) {
  const n = (Array.isArray(result.findings) ? result.findings : []).filter(
    (f) => !f.suppressed && isAlert(f)
  ).length;
  const worst = result.worst;
  if (isIncomplete(result)) {
    const title = worst
      ? `${n} agent-security finding(s), worst: ${worst} (scan incomplete)`
      : 'node9 could not read everything';
    return { title, summary: `${title}\n\nNot read:\n${unreadList(result)}` };
  }
  const reviewN = reviewItems(result).length;
  const title = worst
    ? `${n} agent-security finding(s), worst: ${worst}`
    : reviewN
      ? `No agent-security alerts, ${reviewN} item(s) worth a look`
      : 'No agent-security findings';
  return { title, summary: title };
}

// ── GitHub REST (I/O) ─────────────────────────────────────────────────────────

function gh(method, path, body) {
  const token = process.env.GITHUB_TOKEN;
  return fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'node9-agent-security-action',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function upsertStickyComment(repo, prNumber, markdown) {
  // Find our existing comment (one page of 100 is plenty for a PR).
  const listed = await gh('GET', `/repos/${repo}/issues/${prNumber}/comments?per_page=100`);
  if (listed.ok) {
    const comments = await listed.json();
    const mine = comments.find((c) => typeof c.body === 'string' && c.body.includes(MARKER));
    if (mine) {
      await gh('PATCH', `/repos/${repo}/issues/comments/${mine.id}`, { body: markdown });
      return;
    }
  }
  await gh('POST', `/repos/${repo}/issues/${prNumber}/comments`, { body: markdown });
}

async function postCheckRun(repo, headSha, result, conclusion) {
  await gh('POST', `/repos/${repo}/check-runs`, {
    name: CHECK_NAME,
    head_sha: headSha,
    status: 'completed',
    conclusion,
    output: checkSummary(result),
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

function readEvent() {
  try {
    const raw = fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8');
    const ev = JSON.parse(raw);
    return {
      prNumber: ev.pull_request?.number,
      headSha: ev.pull_request?.head?.sha || process.env.GITHUB_SHA,
    };
  } catch {
    return { prNumber: undefined, headSha: process.env.GITHUB_SHA };
  }
}

async function main() {
  // Deliberately not scanned (I.1): say so, never fall into the unreadable-result path below.
  const skipped = process.env.NODE9_SKIPPED;
  if (skipped) {
    const repo = process.env.GITHUB_REPOSITORY;
    const { prNumber, headSha } = readEvent();
    const why = SKIP_REASONS[skipped] || `the scan was skipped (${skipped}).`;
    console.log(`::warning title=node9 did not scan this PR::${why.replace(/`/g, '')}`);
    if ((process.env.NODE9_COMMENT || 'true') !== 'false' && prNumber) {
      try {
        await upsertStickyComment(repo, prNumber, renderSkipped(skipped));
      } catch (e) {
        console.error(`node9: comment failed (${e.message}), continuing.`);
      }
    }
    if (headSha) {
      try {
        await gh('POST', `/repos/${repo}/check-runs`, {
          name: CHECK_NAME,
          head_sha: headSha,
          status: 'completed',
          conclusion: decideSkipped().conclusion,
          output: { title: 'node9 did not scan this PR', summary: why },
        });
      } catch (e) {
        console.error(`node9: check-run failed (${e.message}), continuing.`);
      }
    }
    console.log(`node9 agent-security: not scanned (${skipped}) · neutral`);
    return decideSkipped().exitCode;
  }

  // Fail-open on our own problems: a broken scan must never block a merge.
  let result;
  try {
    result = JSON.parse(fs.readFileSync(process.env.NODE9_RESULT, 'utf8'));
  } catch (e) {
    console.error(`node9: could not read scan result (${e.message}), skipping (fail-open).`);
    return 0;
  }

  const repo = process.env.GITHUB_REPOSITORY;
  const failOn = (process.env.NODE9_FAIL_ON || 'never').toLowerCase();
  const scope = (process.env.NODE9_FAIL_ON_SCOPE || 'all').toLowerCase();
  const wantComment = (process.env.NODE9_COMMENT || 'true') !== 'false';
  const { prNumber, headSha } = readEvent();
  const { fail, conclusion, exitCode } = decide(
    gateWorst(result, scope),
    failOn,
    !!(result.incomplete || (result.diff && result.diff.incomplete))
  );

  const warning = incompleteWarning(result);
  if (warning) console.log(warning);

  // Inline annotations, on the file the reviewer is already looking at. Printed before the
  // API calls so they still land if commenting fails.
  if ((process.env.NODE9_ANNOTATE || 'true') !== 'false') {
    for (const line of annotationLines(result)) console.log(line);
  }

  if (wantComment && prNumber) {
    try {
      await upsertStickyComment(repo, prNumber, renderComment(result));
    } catch (e) {
      console.error(`node9: comment failed (${e.message}), continuing.`);
    }
  }
  if (headSha) {
    try {
      await postCheckRun(repo, headSha, result, conclusion);
    } catch (e) {
      console.error(`node9: check-run failed (${e.message}), continuing.`);
    }
  }

  console.log(
    `node9 agent-security: worst=${result.worst ?? 'clean'}` +
      (result.diff
        ? ` · introduced=${result.diff.worstIntroduced ?? 'none'} (base ${result.diff.base})`
        : '') +
      ` · fail-on=${failOn}/${scope} · ${fail ? 'FAILING' : conclusion === 'neutral' ? conclusion : 'ok'}`
  );
  return exitCode;
}

// Self-test the pure logic without touching the network.
function selftest() {
  const assert = require('assert');
  // decide()
  assert.deepStrictEqual(decide('high', 'never').exitCode, 0, 'never = report-only');
  assert.strictEqual(decide('high', 'critical').fail, false, 'high < critical → pass');
  assert.strictEqual(decide('critical', 'high').fail, true, 'critical ≥ high → fail');
  assert.strictEqual(decide('high', 'high').fail, true, 'high ≥ high → fail');
  assert.strictEqual(decide(null, 'high').fail, false, 'clean → pass');
  assert.strictEqual(decide(null, 'never').conclusion, 'success', 'clean → success');
  assert.strictEqual(
    decide('medium', 'never').conclusion,
    'neutral',
    'finding + report-only → neutral'
  );
  // renderComment() — structure
  const c = renderComment({
    worst: 'high',
    inspected: ['a', 'b'],
    findings: [
      { severity: 'high', title: 'X', file: 'w.yml', check: 'CI-2', signals: ['s1'], fix: 'do y' },
    ],
  });
  assert.ok(c.startsWith(MARKER), 'marker first (sticky)');
  assert.ok(c.includes('<details>') && c.includes('HIGH: X'), 'raw detail collapsed, not deleted');
  assert.ok(c.includes('✅ Fix') && c.includes('do y'), 'single fix surfaced up front');
  assert.ok(
    renderComment({ worst: null, findings: [] }).includes('No agent-security findings'),
    'clean copy'
  );

  // ── CI-5 scoping ──────────────────────────────────────────────────────────
  const f = (severity, over = {}) => ({
    severity,
    title: 'X',
    file: 'w.yml',
    check: 'CI-2',
    rule: 'CI-2.injectable-workflow',
    signals: ['s'],
    fix: 'do y',
    ...over,
  });
  const withDiff = (diff, findings) => ({ worst: 'critical', findings, inspected: ['a'], diff });

  // The default scope must behave EXACTLY as it did before CI-5 existed.
  assert.strictEqual(
    gateWorst(
      withDiff(
        {
          base: 'ok',
          added: [],
          escalated: [],
          unchanged: [f('critical')],
          removed: [],
          worstIntroduced: null,
        },
        [f('critical')]
      ),
      'all'
    ),
    'critical',
    'scope=all still gates on the repo worst (no behaviour change for existing users)'
  );
  // A dirty repo whose PR introduces nothing must pass — the whole adoptability argument.
  assert.strictEqual(
    gateWorst(
      withDiff(
        {
          base: 'ok',
          added: [],
          escalated: [],
          unchanged: [f('critical')],
          removed: [],
          worstIntroduced: null,
        },
        [f('critical')]
      ),
      'introduced'
    ),
    null,
    'scope=introduced ignores pre-existing findings'
  );
  // An unreadable base must NOT read as "nothing new": the scan degrades worstIntroduced
  // to the absolute worst, and the gate must honour it.
  assert.strictEqual(
    gateWorst(
      withDiff(
        {
          base: 'did-not-run',
          added: [],
          escalated: [],
          unchanged: [f('critical')],
          removed: [],
          worstIntroduced: 'critical',
        },
        [f('critical')]
      ),
      'introduced'
    ),
    'critical',
    'an unreadable base falls back to the strict answer'
  );
  // An older CLI emits no diff; asking for the narrow gate must not silently open it.
  assert.strictEqual(
    gateWorst({ worst: 'critical', findings: [f('critical')] }, 'introduced'),
    'critical',
    'no diff in the result → gate on the repo worst, never on nothing'
  );

  // An incomplete scan must never post a green check, on either scope.
  assert.strictEqual(
    decide(null, 'high', true).conclusion,
    'neutral',
    'incomplete → neutral, never success'
  );
  assert.strictEqual(
    decide(null, 'high', false).conclusion,
    'success',
    'complete + clean → success'
  );
  const partial = withDiff(
    {
      base: 'ok',
      added: [],
      escalated: [],
      unchanged: [],
      removed: [],
      worstIntroduced: null,
      incomplete: true,
    },
    []
  );
  partial.worst = null;
  partial.incomplete = true;
  const partialComment = renderComment(partial);
  assert.ok(
    !partialComment.includes('introduces no agent-security findings'),
    'a partial scan never claims the PR introduced nothing'
  );
  assert.ok(partialComment.includes('could not read everything'), 'a partial scan says so');

  // ── suppression (.node9-ignore.json) ─────────────────────────────────────────
  const sup = { reason: 'accepted, tracked in #412', key: 'k' };
  const mixed = {
    worst: 'medium',
    findings: [f('critical', { suppressed: sup }), f('medium', { file: 'b.yml' })],
    inspected: ['a'],
  };
  assert.strictEqual(annotationLines(mixed).length, 1, 'a suppressed finding is not annotated');
  assert.match(annotationLines(mixed)[0], /file=b\.yml/, 'the unsuppressed one is');
  const c2 = renderComment(mixed);
  assert.ok(c2.includes('1 suppressed'), 'the headline counts suppressed findings');
  assert.ok(
    c2.includes('suppressed: `accepted, tracked in #412`'),
    'the detail shows the reason, as a code span'
  );
  assert.ok(
    !c2.includes('Critical: action needed'),
    'the headline tier ignores the suppressed critical'
  );
  assert.ok(c2.includes('Medium: hardening'), 'and is driven by the unsuppressed medium');
  const allSup = renderComment({
    worst: null,
    findings: [f('critical', { suppressed: sup })],
    inspected: ['a'],
  });
  assert.ok(
    allSup.includes('1 suppressed') || allSup.includes('suppressed:'),
    'all-suppressed still names the suppression'
  );

  // ── review H.6: a suppression reason cannot inject markdown into the comment ──
  const evil = {
    worst: null,
    inspected: ['a'],
    findings: [
      f('medium', {
        suppressed: {
          reason:
            'ok_\n\n</details>\n\n### 🛡️ node9 agent-security · ✅\n\n**safe to merge** <!-- @team `x`',
          key: 'k',
        },
      }),
    ],
  };
  const ce = renderComment(evil);
  assert.strictEqual(
    ce.split('\n').filter((l) => l.startsWith('### 🛡️ node9 agent-security')).length,
    1,
    'exactly one header: a reason cannot forge a second one'
  );
  assert.ok(!/\n### /.test(ce.slice(ce.indexOf('suppressed:'))), 'no heading after the reason');
  assert.ok(
    /suppressed: `[^`\n]*<!-- @team 'x'[^`\n]*`/.test(ce),
    'the reason sits in one code span'
  );

  // ── I.1: under pull_request_target the Action does not scan, and says so ─────
  const sk = renderSkipped('pull_request_target');
  assert.ok(sk.startsWith(MARKER), 'skipped comment is sticky');
  assert.ok(sk.includes('node9 did not scan this PR'), 'skipped comment says it did not scan');
  assert.ok(
    sk.includes('pull_request_target') && sk.includes('`pull_request`'),
    'names the event and the fix'
  );
  assert.ok(!sk.includes('✅'), 'a skipped scan never reads as clean');
  const skd = decideSkipped();
  assert.strictEqual(skd.conclusion, 'neutral', 'skipped → neutral, never success');
  assert.strictEqual(skd.exitCode, 0, 'skipped → never blocks the PR');

  // Annotations follow the same scope.
  const introducedOnly = withDiff(
    {
      base: 'ok',
      added: [f('high', { file: 'new.yml' })],
      escalated: [],
      unchanged: [f('critical')],
      removed: [],
      worstIntroduced: 'high',
    },
    [f('critical'), f('high', { file: 'new.yml' })]
  );
  const anns = annotationLines(introducedOnly);
  assert.strictEqual(anns.length, 1, 'only the introduced finding is annotated');
  assert.match(
    anns[0],
    /^::error file=new\.yml,line=1,title=node9 CI-2\.injectable-workflow::/,
    'workflow-command shape'
  );
  assert.strictEqual(
    annotationLines({ worst: 'high', findings: [f('high'), f('medium')] }).length,
    2,
    'no diff → annotate everything'
  );

  // A clean PR on a dirty repo reads GREEN, and still shows the pile collapsed.
  const cleanPr = renderComment(
    withDiff(
      {
        base: 'ok',
        added: [],
        escalated: [],
        unchanged: [f('critical')],
        removed: [f('medium')],
        worstIntroduced: null,
      },
      [f('critical')]
    )
  );
  assert.ok(cleanPr.includes('introduces no agent-security findings'), 'clean-PR headline');
  assert.ok(cleanPr.includes('It also fixes 1'), 'fixes are credited');
  assert.ok(cleanPr.includes('pre-existing'), 'the pile is still disclosed');
  assert.ok(cleanPr.includes('<details>'), 'the pile is still listed, collapsed');

  // An untrustworthy base must never render as clean.
  const blind = renderComment(
    withDiff(
      {
        base: 'did-not-run',
        added: [],
        escalated: [],
        unchanged: [f('critical')],
        removed: [],
        worstIntroduced: 'critical',
      },
      [f('critical')]
    )
  );
  assert.ok(!blind.includes('introduces no agent-security findings'), 'no false all-clear');
  assert.ok(blind.includes('Could not read the base commit'), 'says why it cannot compare');

  // Erosion is named as erosion.
  const eroded = renderComment(
    withDiff(
      {
        base: 'ok',
        added: [],
        escalated: [{ finding: f('high'), from: 'medium', to: 'high' }],
        unchanged: [],
        removed: [],
        worstIntroduced: 'high',
      },
      [f('high')]
    )
  );
  assert.ok(eroded.includes('widens them'), 'escalation is called out as a removed guardrail');

  // threatLine() — LOAD-BEARING honesty guards (overclaiming here undoes the trust the
  // scanner calibration bought). Derived + severity-tiered.
  const T = (check, severity, signals, companions = []) =>
    threatLine({ check, severity, signals }, [{ check, severity, signals }, ...companions]);

  // critical CI-2 RCE + CI-4 secret on the same file → "run code AND steal secrets".
  assert.match(
    T(
      'CI-2',
      'critical',
      ['agent has broad/write-capable tools (Bash/Write/curl/git push)'],
      [
        {
          check: 'CI-4',
          severity: 'critical',
          signals: ['agent has arbitrary shell (bare Bash) → can read env and exfiltrate'],
        },
      ]
    ),
    /run code on this repo and steal your secrets/,
    'crit RCE+exfil → run-code-and-steal'
  );
  // high CI-2 with pull-requests:write → "approve or merge", NOT "run code".
  const metaHigh = T('CI-2', 'high', ['pull-requests: write', 'agent can approve or merge a PR']);
  assert.match(metaHigh, /approve or merge/, 'high metaWrite → approve/merge PRs');
  assert.doesNotMatch(metaHigh, /run code|steal/i, 'high metaWrite must NOT claim RCE/exfil');
  // MEDIUM must never render an RCE/exfil/"stranger can run code" threat.
  const med = T('CI-2', 'medium', [
    'agent has broad/write-capable tools (Bash/Write/curl/git push)',
  ]);
  assert.doesNotMatch(
    med,
    /run code|steal|arbitrary code/i,
    'medium must stay calm: no breach language'
  );
  assert.match(med, /hardening/i, 'medium → hardening framing');
  // ADVISORY → neutral, no drama.
  assert.doesNotMatch(
    T('CI-2', 'advisory', ['runs with base-repo secrets (pull_request_target)']),
    /stranger can|run code|steal/i,
    'advisory → neutral'
  );
  // CI-6 tiers: critical hidden-chars ≠ high override wording.
  assert.match(T('CI-6', 'critical', []), /hides characters|conceal/i, 'CI-6 crit → concealment');
  assert.match(T('CI-6', 'high', []), /ignore its own rules/i, 'CI-6 high → override');

  console.log('comment.js selftest: OK');
}

if (require.main === module) {
  if (process.argv.includes('--selftest')) {
    selftest();
  } else {
    main()
      .then((code) => process.exit(code))
      .catch((e) => {
        console.error(`node9: unexpected error (${e.message}), failing open.`);
        process.exit(0);
      });
  }
}

module.exports = {
  decide,
  renderComment,
  checkSummary,
  incompleteWarning,
  annotationLines,
  threatLine,
  mechanism,
  renderDetail,
};
