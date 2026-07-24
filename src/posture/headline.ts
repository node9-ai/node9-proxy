// src/posture/headline.ts
// Derives the "Biggest risk" headline from the finding set.
//
// The flat list of findings answers "what's true"; the headline answers
// "so what — what's the actual attack, and what do I do first." It prioritizes
// risk *chains* (readable secrets + open egress = exfiltration) over isolated
// findings, and picks the single highest-leverage action.

import type { Finding, Headline, Severity } from './types';

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  advisory: 3,
};

function worstFinding(findings: Finding[]): Finding | undefined {
  // Tie-break beyond severity: the headline surfaces finding CONTENT, so the
  // pick must not depend on check execution order.
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      a.category.localeCompare(b.category) ||
      a.title.localeCompare(b.title)
  )[0];
}

/**
 * Self-contained action text derived from a finding: its own `fix` minus any
 * "Fix it now:" prefix (render prepends "Do this first:"), plus the first
 * concrete location so the CTA names the actual evidence — never a canned
 * exemplar (a headline that mislabels the mechanism is worse than silence).
 * `detail` holds secret types + locations only, never values (see secrets.ts).
 */
function actionFromFinding(f: Finding | undefined): string | null {
  if (!f?.fix) return null;
  const fix = f.fix.replace(/^fix it now:\s*/i, '');
  const where =
    f.detail.length === 0
      ? ''
      : f.detail.length === 1
        ? ` — found: ${f.detail[0]}`
        : ` — found: ${f.detail[0]} and ${f.detail.length - 1} more`;
  return fix + where;
}

/**
 * Pick the scariest TRUE story + the one next step. Returns null when there's
 * nothing real to narrate (no findings, or only advisory ones node9 can't fix).
 */
export function deriveHeadline(allFindings: Finding[]): Headline | null {
  // Only OPEN findings tell the story — a covered Secrets must never feed
  // "an agent can read your credentials." Exclude covered + can't-fix.
  const findings = allFindings.filter(
    (f) => f.coverage?.state !== 'covered' && f.coverage?.state !== 'cant-fix'
  );

  // Advisory-only (isolation/inbound) → no scary chain to call out; the score
  // and the rows speak for themselves.
  if (findings.length === 0 || findings.every((f) => f.severity === 'advisory')) return null;

  const has = (category: string) => findings.some((f) => f.category === category);
  const secrets = has('Secrets');
  const egressOpen = has('Egress');
  const noIsolation = has('Isolation');
  const gateWeak = has('Approval gate');
  const notWired = findings.some((f) => f.category === 'Coverage' && f.severity === 'critical');
  const observeOnly = findings.some((f) => f.category === 'Coverage' && f.severity === 'high');

  // ── The risk narrative: the scariest TRUE story ──────────────────────────
  let risk: string;
  if (secrets && egressOpen) {
    risk =
      'An agent on this host can read the credentials on this box and send them to any host' +
      (noIsolation ? ', and there is no container around it' : '') +
      '. One poisoned input — a malicious file, or a prompt-injection in a page it reads — is all it takes.';
  } else if (secrets) {
    risk =
      'An agent on this host can read the credentials on this box' +
      (noIsolation ? ' with no sandbox around it' : '') +
      '. A single poisoned instruction would expose those keys.';
  } else if (egressOpen && gateWeak) {
    risk =
      'An agent here can run unrestricted commands and reach any host — an open path for a poisoned instruction to exfiltrate data or damage the box.';
  } else if (egressOpen) {
    risk =
      'An agent here can reach any host on the internet — an open exfiltration path the moment it is compromised.';
  } else if (gateWeak) {
    risk =
      'Destructive commands are not reliably blocked here — an agent given a bad instruction could damage the box.';
  } else {
    risk = worstFinding(findings)?.title ?? 'Review the findings below.';
  }

  // ── The one next step: highest leverage first ────────────────────────────
  let action: string;
  if (notWired) {
    // node9 isn't in-path — and whoever's reading this may not even have it
    // installed (e.g. they ran `npx node9-ai posture` cold), so lead with an
    // install+init chain that works either way (`npm i -g` is a no-op if present).
    action =
      'Install node9 and put it in-path: `npm i -g node9-ai && node9 init` — nothing here is enforced until you do.';
  } else if (observeOnly) {
    action = 'Switch node9 to enforcing mode — right now it is only watching, not blocking.';
  } else if (egressOpen) {
    action =
      'lock egress to an allowlist (node9 can enforce it) — it closes the exit the exfiltration needs.';
  } else if (secrets) {
    // The finding is the source of truth — its fix names the exact command and
    // its detail names the actual file. The fallback carries the command but
    // asserts NO specifics (a canned path list here is how the 07-23 repro
    // showed "~/.ssh, ~/.aws" against a secret living in ~/.claude.json).
    action =
      actionFromFinding(worstFinding(findings.filter((f) => f.category === 'Secrets'))) ??
      'node9 can block reads of sensitive credential files in-path (`node9 shield enable project-jail`).';
  } else if (gateWeak) {
    action = 'node9 can enforce destructive-command blocking in-path.';
  } else {
    action = actionFromFinding(worstFinding(findings)) ?? 'Review the findings below.';
  }

  return { risk, action };
}
