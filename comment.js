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
function decide(worst, failOn) {
  const threshold = RANK[failOn]; // undefined for 'never'/unknown → never fail
  const fail = !!(threshold && worst && RANK[worst] >= threshold);
  const conclusion = fail ? 'failure' : worst ? 'neutral' : 'success';
  return { fail, conclusion, exitCode: fail ? 1 : 0 };
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
        : 'A committed agent config grants broad tools — worth scoping down.';
    case 'CI-3':
      return "An MCP server runs an unpinned package — a compromised release would run in every contributor's agent.";
    case 'CI-6':
      if (sev === 'critical')
        return 'An agent instruction file hides characters that conceal instructions from human review.';
      if (sev === 'high')
        return 'An agent instruction file tells the agent to ignore its own rules.';
      if (sev === 'medium')
        return 'An agent instruction file points the agent at a risky action — review it.';
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
        : "Anyone who can trigger this workflow reaches the agent, and it runs with your repo's permissions — no human approves first.";
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

/** The collapsed fact-list — the previous renderComment body, kept verbatim for power users. */
function renderDetail(result) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const L = [];
  L.push(
    `<details><summary>${findings.length} finding(s) · ${[...new Set(findings.map((f) => f.check))].join(', ')} · full detail</summary>`
  );
  L.push('');
  for (const f of findings) {
    L.push(`**${ICON[f.severity] ?? '•'} ${String(f.severity).toUpperCase()} — ${f.title}**`);
    L.push(`\`${f.file}${f.line ? ':' + f.line : ''}\` · ${f.check}`);
    for (const s of f.signals ?? []) L.push(`- ${s}`);
    if (f.mitigations?.length) L.push(`- _mitigated:_ ${f.mitigations.join('; ')}`);
    if (f.fix) L.push(`- → **Fix:** ${f.fix}`);
    L.push('');
  }
  L.push('</details>');
  return L.join('\n');
}

/** Render the sticky comment: lead with the ATTACK STORY (threat → mechanism → single fix),
 *  raw findings collapsed into <details>. Same ScanResult data, reframed for impact. */
function renderComment(result) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const worst = result.worst;
  const L = [MARKER];
  if (findings.length === 0) {
    L.push('### 🛡️ node9 agent-security · ✅');
    L.push('');
    L.push(
      'No agent-security findings — no injectable workflows, unsafe agent configs, or unpinned MCP servers.'
    );
    return L.join('\n');
  }
  const anchor = [...findings].sort((a, b) => RANK[b.severity] - RANK[a.severity])[0];
  const companions = findings.filter((f) => f.file === anchor.file); // chain-merge same-file findings
  const tier =
    worst === 'critical'
      ? 'Critical — action needed'
      : worst === 'high'
        ? 'High — action needed'
        : worst === 'medium'
          ? 'Medium — hardening'
          : 'Advisory — note';

  L.push(`### 🛡️ node9 agent-security · ${ICON[worst] ?? '🟢'} ${tier}`);
  L.push('');
  L.push(`**${threatLine(anchor, companions)}**`);
  const mech = mechanism(anchor, companions);
  if (mech) {
    L.push('');
    L.push(mech);
  }
  const fixes = [...new Set(companions.map((f) => f.fix).filter(Boolean))];
  if (fixes.length === 1) {
    L.push('');
    L.push(`**✅ Fix** in \`${anchor.file}\`: ${fixes[0]}`);
  } else if (fixes.length > 1) {
    L.push('');
    L.push(`**✅ Fix** in \`${anchor.file}\`:`);
    for (const fx of fixes) L.push(`- ${fx}`);
  }
  L.push('');
  L.push(renderDetail(result));
  L.push('');
  L.push(
    "<sub>node9 scans committed agent config statically — it never runs your repo's code. · Catch this on every PR → node9.ai</sub>"
  );
  return L.join('\n');
}

/** A check-run output summary (title + short body). */
function checkSummary(result) {
  const n = Array.isArray(result.findings) ? result.findings.length : 0;
  const worst = result.worst;
  const title = worst
    ? `${n} agent-security finding(s), worst: ${worst}`
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
  // Fail-open on our own problems: a broken scan must never block a merge.
  let result;
  try {
    result = JSON.parse(fs.readFileSync(process.env.NODE9_RESULT, 'utf8'));
  } catch (e) {
    console.error(`node9: could not read scan result (${e.message}) — skipping (fail-open).`);
    return 0;
  }

  const repo = process.env.GITHUB_REPOSITORY;
  const failOn = (process.env.NODE9_FAIL_ON || 'never').toLowerCase();
  const wantComment = (process.env.NODE9_COMMENT || 'true') !== 'false';
  const { prNumber, headSha } = readEvent();
  const { fail, conclusion, exitCode } = decide(result.worst, failOn);

  if (wantComment && prNumber) {
    try {
      await upsertStickyComment(repo, prNumber, renderComment(result));
    } catch (e) {
      console.error(`node9: comment failed (${e.message}) — continuing.`);
    }
  }
  if (headSha) {
    try {
      await postCheckRun(repo, headSha, result, conclusion);
    } catch (e) {
      console.error(`node9: check-run failed (${e.message}) — continuing.`);
    }
  }

  console.log(
    `node9 agent-security: worst=${result.worst ?? 'clean'} · fail-on=${failOn} · ${fail ? 'FAILING' : 'ok'}`
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
  assert.ok(c.includes('<details>') && c.includes('HIGH — X'), 'raw detail collapsed, not deleted');
  assert.ok(c.includes('✅ Fix') && c.includes('do y'), 'single fix surfaced up front');
  assert.ok(
    renderComment({ worst: null, findings: [] }).includes('No agent-security findings'),
    'clean copy'
  );

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
    'medium must stay calm — no breach language'
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
        console.error(`node9: unexpected error (${e.message}) — failing open.`);
        process.exit(0);
      });
  }
}

module.exports = { decide, renderComment, checkSummary, threatLine, mechanism, renderDetail };
