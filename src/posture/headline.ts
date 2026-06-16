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
  return [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])[0];
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
    action = 'Run `node9 setup` — node9 is not in-path yet, so nothing here is enforced.';
  } else if (observeOnly) {
    action = 'Switch node9 to enforcing mode — right now it is only watching, not blocking.';
  } else if (egressOpen) {
    action =
      'lock egress to an allowlist (node9 can enforce it) — it closes the exit the exfiltration needs.';
  } else if (secrets) {
    action = 'node9 can block reads of sensitive paths (~/.ssh, ~/.aws) in-path.';
  } else if (gateWeak) {
    action = 'node9 can enforce destructive-command blocking in-path.';
  } else {
    action = worstFinding(findings)?.fix ?? 'Review the findings below.';
  }

  return { risk, action };
}
